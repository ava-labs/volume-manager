use std::{
    env, fs,
    io::{self, Error, ErrorKind},
    path::{Path, PathBuf},
};

use aws_manager::{self, ec2};
use aws_sdk_ec2::types::{
    Filter, ResourceType, Tag, TagSpecification, Volume, VolumeAttachmentState, VolumeState,
    VolumeType,
};
use chrono::{DateTime, Utc};
use clap::{crate_version, value_parser, Arg, Command};
use path_clean::PathClean;
use tokio::time::{sleep, Duration};
use walkdir::WalkDir;

pub const NAME: &str = "aws-volume-provisioner";

pub fn new() -> Command {
    Command::new(NAME)
        .version(crate_version!())
        .about("Provisions the EBS volume to the local availability zone")
        .long_about(
            "


The availability zone is automatically fetched.

Commands may run multiple times with idempotency.

Requires IAM instance role of: ec2:DescribeVolumes, ec2:CreateVolume, and ec2:AttachVolume.

e.g.,

$ aws-volume-provisioner \
--log-level=info \
--initial-wait-random-seconds=70 \
--id-tag-key=Id \
--id-tag-value=TEST-ID \
--kind-tag-key=Kind \
--kind-tag-value=aws-volume-provisioner \
--ec2-tag-asg-name-key=ASG_NAME \
--asg-tag-key=autoscaling:groupName \
--volume-type=gp3 \
--volume-size=400 \
--volume-iops=3000 \
--volume-throughput=500 \
--ebs-device-name=/dev/xvdb \
--block-device-name=/dev/nvme1n1 \
--filesystem-name=ext4 \
--mount-directory-path=/data

",
        )
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .num_args(1)
                .value_parser(["debug", "info"])
                .default_value("info"),
        )
        .arg(
            Arg::new("REGION")
                .long("region")
                .help("Sets the AWS region")
                .required(true)
                .num_args(1)
                .default_value("us-west-2"),
        )
        .arg(
            Arg::new("INITIAL_WAIT_RANDOM_SECONDS")
                .long("initial-wait-random-seconds")
                .help("Sets the maximum number of seconds to wait (value chosen at random with the range)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u32))
                .default_value("5"),
        )
        .arg(
            Arg::new("ID_TAG_KEY")
                .long("id-tag-key")
                .help("Sets the key for the EBS volume 'Id' tag (must be set via EC2 tags, or used for EBS volume creation)")
                .required(true)
                .num_args(1)
                .default_value("Id"),
        )
        .arg(
            Arg::new("ID_TAG_VALUE")
                .long("id-tag-value")
                .help("Sets the value for the EBS volume 'Id' tag key (must be set via EC2 tags)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("KIND_TAG_KEY")
                .long("kind-tag-key")
                .help("Sets the key for the EBS volume 'Kind' tag (must be set via EC2 tags, or used for EBS volume creation)")
                .required(true)
                .num_args(1)
                .default_value("Kind"),
        )
        .arg(
            Arg::new("KIND_TAG_VALUE")
                .long("kind-tag-value")
                .help("Sets the value for the EBS volume 'Kind' tag key (must be set via EC2 tags)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("EC2_TAG_ASG_NAME_KEY")
                .long("ec2-tag-asg-name-key")
                .help("Sets the key of the ASG name tag")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("ASG_TAG_KEY")
                .long("asg-tag-key")
                .help("Sets the key for the EBS volume asg name tag (must be set via EC2 tags, or used for EBS volume creation)")
                .required(true)
                .num_args(1)
                .default_value("autoscaling:groupName"),
        )
        .arg(
            Arg::new("FIND_REUSABLE_RETRIES")
                .long("describe-local-retries")
                .help("Sets the number of describe call retries until it finds one before creating one")
                .required(false)
                .value_parser(value_parser!(usize))
                .num_args(1)
                .default_value("15"),
        )
        .arg(
            Arg::new("VOLUME_TYPE")
                .long("volume-type")
                .help("Sets the volume size in GB")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("VOLUME_SIZE")
                .long("volume-size")
                .help("Sets the volume size in GB")
                .required(true)
                .value_parser(value_parser!(u32))
                .num_args(1)
                .default_value("400"),
        )
        .arg(
            Arg::new("VOLUME_IOPS")
                .long("volume-iops")
                .help("Sets the volume IOPS")
                .required(true)
                .value_parser(value_parser!(u32))
                .num_args(1)
                .default_value("3000"),
        )
        .arg(
            Arg::new("VOLUME_THROUGHPUT")
                .long("volume-throughput")
                .help("Sets the volume throughput")
                .required(true)
                .value_parser(value_parser!(u32))
                .num_args(1)
                .default_value("500"),
        )
        .arg(
            Arg::new("EBS_DEVICE_NAME")
                .long("ebs-device-name")
                .help("Sets the EBS device name (e.g., /dev/xvdb)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("BLOCK_DEVICE_NAME")
                .long("block-device-name")
                .help("Sets the OS-level block device name (e.g., /dev/nvme1n1)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("FILESYSTEM_NAME")
                .long("filesystem-name")
                .help("Sets the filesystem name to create (e.g., ext4)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("MOUNT_DIRECTORY_PATH")
                .long("mount-directory-path")
                .help("Sets the directory path to mount onto the device")
                .required(true)
                .num_args(1),
        )
}

/// Defines flag options.
pub struct Flags {
    pub log_level: String,
    pub region: String,
    pub initial_wait_random_seconds: u32,

    pub id_tag_key: String,
    pub id_tag_value: String,
    pub kind_tag_key: String,
    pub kind_tag_value: String,
    pub ec2_tag_asg_name_key: String,
    pub asg_tag_key: String,

    pub find_reusable_retries: usize,

    pub volume_type: String,
    pub volume_size: u32,
    pub volume_iops: u32,
    pub volume_throughput: u32,

    pub ebs_device_name: String,
    pub block_device_name: String,
    pub filesystem_name: String,
    pub mount_directory_path: String,
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    println!("{} version: {}", NAME, crate_version!());

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );
    log::info!(
        "starting 'aws-volume-provisioner' on the region '{}'",
        opts.region
    );

    let shared_config =
        aws_manager::load_config(Some(opts.region.clone()), Some(Duration::from_secs(30))).await;
    let ec2_manager = ec2::Manager::new(&shared_config);

    let az = ec2::metadata::fetch_availability_zone()
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed fetch_availability_zone '{}'", e),
            )
        })?;
    let ec2_instance_id = ec2::metadata::fetch_instance_id().await.map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("failed fetch_instance_id '{}'", e),
        )
    })?;

    log::info!("fetching the tag value for {}", opts.ec2_tag_asg_name_key);
    let tags = ec2_manager
        .fetch_tags(&ec2_instance_id)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed fetch_tags {}", e)))?;

    let mut asg_tag_value = String::new();
    for c in tags {
        let k = c.key().unwrap();
        let v = c.value().unwrap();

        log::info!("EC2 tag key='{}', value='{}'", k, v);
        if k == opts.ec2_tag_asg_name_key {
            asg_tag_value = v.to_string();
            break;
        }
    }
    if asg_tag_value.is_empty() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("{} is empty", opts.ec2_tag_asg_name_key),
        ));
    }

    let sleep_sec = if opts.initial_wait_random_seconds > 0 {
        random_manager::u32() % opts.initial_wait_random_seconds
    } else {
        0
    };
    if sleep_sec > 0 {
        log::info!("waiting for random seconds {}", sleep_sec);
        sleep(Duration::from_secs(sleep_sec as u64)).await;
    } else {
        log::info!("skipping random sleep...");
    }

    log::info!(
        "checking if the local instance has an already attached volume with region '{:?}', AZ '{}', device '{}', instance Id '{}', id tag value '{}' (for reuse)",
        shared_config.region(),
        az,
        opts.ebs_device_name,
        ec2_instance_id,
        opts.id_tag_value,
    );

    // ref. https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html
    let filters: Vec<Filter> = vec![
        Filter::builder()
            .set_name(Some(String::from("attachment.device")))
            .set_values(Some(vec![opts.ebs_device_name.clone()]))
            .build(),
        // ensures the call only returns the volume that is attached to this local instance
        Filter::builder()
            .set_name(Some(String::from("attachment.instance-id")))
            .set_values(Some(vec![ec2_instance_id.clone()]))
            .build(),
        // ensures the call only returns the volume that is currently attached
        Filter::builder()
            .set_name(Some(String::from("attachment.status")))
            .set_values(Some(vec![String::from("attached")]))
            .build(),
        // ensures the call only returns the volume that is currently in use
        Filter::builder()
            .set_name(Some(String::from("status")))
            .set_values(Some(vec![String::from("in-use")]))
            .build(),
        Filter::builder()
            .set_name(Some(String::from("availability-zone")))
            .set_values(Some(vec![az.clone()]))
            .build(),
        Filter::builder()
            .set_name(Some(format!("tag:{}", opts.id_tag_key)))
            .set_values(Some(vec![opts.id_tag_value.clone()]))
            .build(),
        Filter::builder()
            .set_name(Some(format!("tag:{}", opts.kind_tag_key)))
            .set_values(Some(vec![opts.kind_tag_value.clone()]))
            .build(),
        Filter::builder()
            .set_name(Some(format!("tag:{}", opts.asg_tag_key)))
            .set_values(Some(vec![asg_tag_value.clone()]))
            .build(),
        Filter::builder()
            .set_name(Some(String::from("volume-type")))
            .set_values(Some(vec![opts.volume_type.clone()]))
            .build(),
    ];
    let local_attached_volumes =
        ec2_manager
            .describe_volumes(Some(filters))
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!(
                        "failed ec2_manager.describe_volumes {} (retryable {})",
                        e.message(),
                        e.retryable()
                    ),
                )
            })?;

    log::info!(
        "found {} local attached volume for the local EC2 instance",
        local_attached_volumes.len()
    );

    // only make filesystem (format) for initial creation
    // do not format volume for already attached EBS volumes
    // do not format volume for reused EBS volumes
    let mut need_mkfs = true;

    let local_attached_volume_found = local_attached_volumes.len() == 1;
    if local_attached_volume_found {
        log::info!("no need mkfs because the local EC2 instance already has an volume attached");
        need_mkfs = false;
    } else {
        log::info!("local EC2 instance '{}' has no attached volume, querying available volumes by AZ '{}' and Id '{}'", ec2_instance_id, az, opts.id_tag_value);

        // ref. <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html>
        let filters: Vec<Filter> = vec![
            // ensures the call only returns the volume that is currently available
            Filter::builder()
                .set_name(Some(String::from("status")))
                .set_values(Some(vec![String::from("available")]))
                .build(),
            Filter::builder()
                .set_name(Some(String::from("availability-zone")))
                .set_values(Some(vec![az.clone()]))
                .build(),
            Filter::builder()
                .set_name(Some(format!("tag:{}", opts.id_tag_key)))
                .set_values(Some(vec![opts.id_tag_value.clone()]))
                .build(),
            Filter::builder()
                .set_name(Some(format!("tag:{}", opts.kind_tag_key)))
                .set_values(Some(vec![opts.kind_tag_value.clone()]))
                .build(),
            Filter::builder()
                .set_name(Some(format!("tag:{}", opts.asg_tag_key)))
                .set_values(Some(vec![asg_tag_value.clone()]))
                .build(),
            Filter::builder()
                .set_name(Some(String::from("volume-type")))
                .set_values(Some(vec![opts.volume_type.clone()]))
                .build(),
        ];

        // NOTE: sometimes EBS returns zero volume even if there's a volume
        // with matching tags... retry just in case...
        let mut described_or_created_volumes: Vec<Volume> = Vec::new();
        for i in 0..opts.find_reusable_retries {
            log::info!("[{i}] trying describe_volumes to find reusable volumes");
            described_or_created_volumes = ec2_manager
                .describe_volumes(Some(filters.clone()))
                .await
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!(
                            "failed ec2_manager.describe_volumes {} (retryable {})",
                            e.message(),
                            e.retryable()
                        ),
                    )
                })?;

            log::info!(
                "described_or_created_volumes {}",
                described_or_created_volumes.len()
            );
            if described_or_created_volumes.len() > 0 {
                break;
            }

            log::info!("no volume found... retrying in case of inconsistent/stale EBS describe_volumes API response");
            sleep(Duration::from_secs(3)).await;
        }

        let mut reusable_volume_found_in_az = !described_or_created_volumes.is_empty();

        // if we don't check whether the other instance in the same AZ has "just" created
        // this EBS volume or not, this can be racey -- two instances may be trying to attach
        // the same EBS volume to two different instances at the same time
        if reusable_volume_found_in_az {
            if let Some(tags) = described_or_created_volumes[0].tags() {
                for tag in tags.iter() {
                    if let Some(tag_key) = tag.key() {
                        if !tag_key.eq(VOLUME_LEASE_HOLD_KEY) {
                            continue;
                        }

                        let tag_val = tag.value().expect("unexpected empty tag value");
                        log::info!("found leasing tag '{}' and '{}'", tag_key, tag_val);

                        let (leasing_instance, leased_at) =
                            parse_volume_lease_hold_key_value(tag_val)?;

                        // only reuse iff:
                        // (1) leased by the same local EC2 instance (restarted volume provisioner)
                        // (2) leased by the other EC2 instance but >10-minute ago

                        // (1) leased by the same local EC2 instance (restarted volume provisioner)
                        if leasing_instance.eq(&ec2_instance_id) {
                            reusable_volume_found_in_az = true;
                            break;
                        }

                        let now: DateTime<Utc> = Utc::now();
                        let now_unix = now.timestamp();
                        let lease_delta = now_unix - leased_at;
                        log::info!("lease timestamp delta is {}", lease_delta);

                        if lease_delta > 600 {
                            // (2) leased by the other EC2 instance but >10-minute ago
                            reusable_volume_found_in_az = true;
                            log::info!("lease delta from the other instance is over 10-minute, so we take over...")
                        } else {
                            log::info!("lease delta from the other instance is still within 10-minute, so we don't take over...")
                        }

                        break;
                    }
                }
            }
        }

        let now: DateTime<Utc> = Utc::now();
        let unix_ts = now.timestamp();

        if reusable_volume_found_in_az {
            log::info!("found reusable, available volume for AZ '{}' and id tag value '{}', attaching '{:?}' to the local EC2 instance", az, opts.id_tag_value, described_or_created_volumes[0]);

            log::info!("updating lease holder tag key for the EBS volume...");

            // ref. https://docs.aws.amazon.com/cli/latest/reference/ec2/create-tags.html
            ec2_manager
                .cli
                .create_tags()
                .resources(described_or_created_volumes[0].volume_id().unwrap())
                .tags(
                    Tag::builder()
                        .key(VOLUME_LEASE_HOLD_KEY.to_string())
                        .value(format!("{}_{}", ec2_instance_id.clone(), unix_ts))
                        .build(),
                )
                .send()
                .await
                .map_err(|e| Error::new(ErrorKind::Other, format!("failed create_tags '{}'", e)))?;

            // do not "mkfs" to retain the previous state
            log::info!("no need mkfs because we are attaching the existing available volume to the local EC2 instance, and retain previous state");
            need_mkfs = false;
        } else {
            log::info!(
                "no reusable, available volume for AZ '{}' and id tag value '{}', must create one in the AZ with size {}, IOPS {}, throughput {}",
                az,
                opts.id_tag_value,
                opts.volume_size,
                opts.volume_iops,
                opts.volume_throughput,
            );

            log::info!("sending 'create_volume' request with tags");

            // ref. https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateVolume.html
            let resp = ec2_manager
                .cli
                .create_volume()
                .availability_zone(az)
                .volume_type(VolumeType::from(opts.volume_type.as_str()))
                .size(opts.volume_size as i32)
                .iops(opts.volume_iops as i32)
                .throughput(opts.volume_throughput as i32)
                .encrypted(true)
                .tag_specifications(
                    TagSpecification::builder()
                        .resource_type(ResourceType::Volume)
                        .tags(
                            Tag::builder()
                                .key(String::from("Name"))
                                .value(asg_tag_value.clone())
                                .build(),
                        )
                        .tags(
                            Tag::builder()
                                .key(opts.id_tag_key.clone())
                                .value(opts.id_tag_value.clone())
                                .build(),
                        )
                        .tags(
                            Tag::builder()
                                .key(opts.kind_tag_key.clone())
                                .value(opts.kind_tag_value.clone())
                                .build(),
                        )
                        .tags(
                            Tag::builder()
                                .key(opts.asg_tag_key.clone())
                                .value(asg_tag_value.clone())
                                .build(),
                        )
                        .tags(
                            Tag::builder()
                                .key(VOLUME_LEASE_HOLD_KEY.to_string())
                                .value(format!("{}_{}", ec2_instance_id.clone(), unix_ts))
                                .build(),
                        )
                        .build(),
                )
                .send()
                .await
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("failed ec2_manager.cli.create_volume {}", e),
                    )
                })?;
            let volume_id = resp.volume_id().unwrap();
            log::info!("created an EBS volume '{}'", volume_id);

            sleep(Duration::from_secs(10)).await;

            let volume = ec2_manager
                .poll_volume_state(
                    volume_id.to_string(),
                    VolumeState::Available,
                    Duration::from_secs(120),
                    Duration::from_secs(5),
                )
                .await
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!(
                            "failed ec2_manager.poll_volume_state {} (retryable {})",
                            e.message(),
                            e.retryable()
                        ),
                    )
                })?;
            log::info!("polled volume after create: {:?}", volume);

            described_or_created_volumes.push(volume.unwrap());
        };

        let volume_id = described_or_created_volumes[0].volume_id().unwrap();
        log::info!("attaching the volume {} to the local instance", volume_id);

        // ref. https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AttachVolume.html
        ec2_manager
            .cli
            .attach_volume()
            .device(opts.ebs_device_name.clone())
            .volume_id(volume_id)
            .instance_id(ec2_instance_id)
            .send()
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("failed ec2_manager.cli.attach_volume {}", e),
                )
            })?;
    }

    sleep(Duration::from_secs(2)).await;

    log::info!("now mounting the attached EBS volume to the local EC2 instance");
    let volume = ec2_manager
        .poll_local_volume_by_attachment_state(
            None,
            opts.ebs_device_name,
            VolumeAttachmentState::Attached,
            Duration::from_secs(180),
            Duration::from_secs(10),
        )
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!(
                    "failed ec2_manager.poll_local_volume_by_attachment_state {} (retryable {})",
                    e.message(),
                    e.retryable()
                ),
            )
        })?;
    log::info!("successfully polled volume {:?}", volume);

    if need_mkfs {
        ec2::disk::make_filesystem(&opts.filesystem_name, &opts.block_device_name)?;
    } else {
        log::info!("skipped mkfs to retain existing data");
    }

    log::info!("mkdir {}", opts.mount_directory_path);
    fs::create_dir_all(&opts.mount_directory_path)?;

    log::info!("sleep before mounting the file system");
    sleep(Duration::from_secs(5)).await;

    // check before mount
    let (blk_lists, _) = command_manager::run("lsblk")?;
    println!("\n\n'lsblk' output:\n\n{}\n", blk_lists);
    let (df_output, _) = command_manager::run("df -h")?;
    println!("\n\n'df -h' output:\n\n{}\n\n", df_output);

    ec2::disk::mount_filesystem(
        &opts.filesystem_name,
        &opts.block_device_name,
        &opts.mount_directory_path,
    )?;

    ec2::disk::update_fstab(
        &opts.filesystem_name,
        &opts.block_device_name,
        &opts.mount_directory_path,
    )?;

    log::info!("mounting all");
    command_manager::run("sudo mount --all")?;

    // check after mount
    let (blk_lists, _) = command_manager::run("lsblk")?;
    println!("\n\n'lsblk' output:\n\n{}\n", blk_lists);
    assert!(blk_lists.contains(&opts.block_device_name.trim_start_matches("/dev/")));
    assert!(blk_lists.contains(&opts.mount_directory_path));

    let (df_output, _) = command_manager::run("df -h")?;
    println!("\n\n'df -h' output:\n\n{}\n\n", df_output);
    assert!(df_output.contains(&opts.block_device_name.trim_start_matches("/dev/")));
    assert!(df_output.contains(&opts.mount_directory_path));

    log::info!("walking directory {}", opts.mount_directory_path);
    let mut cnt = 0;
    for entry in WalkDir::new(&opts.mount_directory_path).into_iter() {
        let entry = match entry {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed walk dir {} ({})", opts.mount_directory_path, e),
                ));
            }
        };

        let full_path = absolute_path(entry.path())?;
        log::info!("listing mounted directory: '{:?}'", full_path);
        cnt += 1;
        if cnt > 20 {
            break;
        }
    }

    log::info!("successfully mounted and provisioned the volume!");
    Ok(())
}

/// Tag key that presents the lease holder.
/// The value is the instance ID and unix timestamps.
/// For example, "i-12345678_1662596730" means "i-12345678" acquired the lease
/// for this volume at the unix timestamp "1662596730".
const VOLUME_LEASE_HOLD_KEY: &str = "LeaseHold";

/// RUST_LOG=debug cargo test --package aws-volume-provisioner -- test_parse_volume_lease_hold_key_value --exact --show-output
#[test]
fn test_parse_volume_lease_hold_key_value() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ec2_instance_id = "i-12345678";
    let now: DateTime<Utc> = Utc::now();
    let unix_ts = now.timestamp();

    let k = format!("{}_{}", ec2_instance_id.clone(), unix_ts);
    let (a, b) = parse_volume_lease_hold_key_value(&k).expect("failed to parse");

    assert_eq!(ec2_instance_id, a);
    assert_eq!(unix_ts, b);
}

pub fn parse_volume_lease_hold_key_value(s: &str) -> io::Result<(String, i64)> {
    let ss: Vec<&str> = s.split("_").collect();
    let ec2_instance_id = ss[0].to_string();

    let unix_ts = ss[1].parse::<i64>().map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("failed parse unix timestamp '{}' '{}'", ss[1], e),
        )
    })?;
    Ok((ec2_instance_id, unix_ts))
}

fn absolute_path(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let p = path.as_ref();

    let ap = if p.is_absolute() {
        p.to_path_buf()
    } else {
        env::current_dir()?.join(p)
    }
    .clean();

    Ok(ap)
}
