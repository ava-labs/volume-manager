pub mod command;

use std::io;

pub const APP_NAME: &str = "aws-volume-provisioner";

#[tokio::main]
async fn main() -> io::Result<()> {
    let matches = command::new().get_matches();

    let log_level = matches
        .get_one::<String>("LOG_LEVEL")
        .unwrap_or(&String::from("info"))
        .clone();

    let initial_wait_random_seconds = matches
        .get_one::<u32>("INITIAL_WAIT_RANDOM_SECONDS")
        .unwrap_or(&5)
        .clone();

    let id_tag_key = matches.get_one::<String>("ID_TAG_KEY").unwrap().clone();
    let id_tag_value = matches.get_one::<String>("ID_TAG_VALUE").unwrap().clone();
    let kind_tag_key = matches.get_one::<String>("KIND_TAG_KEY").unwrap().clone();
    let kind_tag_value = matches.get_one::<String>("KIND_TAG_VALUE").unwrap().clone();
    let ec2_tag_asg_name_key = matches
        .get_one::<String>("EC2_TAG_ASG_NAME_KEY")
        .unwrap()
        .clone();
    let asg_tag_key = matches.get_one::<String>("ASG_TAG_KEY").unwrap().clone();

    let volume_type = matches
        .get_one::<String>("VOLUME_TYPE")
        .unwrap_or(&String::from("gp3"))
        .clone();

    let volume_size = matches
        .get_one::<u32>("VOLUME_SIZE")
        .unwrap_or(&400)
        .clone();
    assert!(volume_size < i32::MAX as u32);

    let volume_iops = matches
        .get_one::<u32>("VOLUME_IOPS")
        .unwrap_or(&3000)
        .clone();
    assert!(volume_iops < i32::MAX as u32);

    let volume_throughput = matches
        .get_one::<u32>("VOLUME_THROUGHPUT")
        .unwrap_or(&500)
        .clone();
    assert!(volume_throughput < i32::MAX as u32);

    let ebs_device_name = matches
        .get_one::<String>("EBS_DEVICE_NAME")
        .unwrap_or(&String::from("/dev/xvdb"))
        .clone();
    let block_device_name = matches
        .get_one::<String>("BLOCK_DEVICE_NAME")
        .unwrap_or(&String::from("/dev/nvme1n1"))
        .clone();
    let filesystem_name = matches
        .get_one::<String>("FILESYSTEM_NAME")
        .unwrap_or(&String::from("ext4"))
        .clone();
    let mount_directory_path = matches
        .get_one::<String>("MOUNT_DIRECTORY_PATH")
        .unwrap_or(&String::from("/data"))
        .clone();

    let opts = command::Flags {
        log_level,
        region: matches.get_one::<String>("REGION").unwrap().clone(),
        initial_wait_random_seconds,
        id_tag_key,
        id_tag_value,
        kind_tag_key,
        kind_tag_value,
        ec2_tag_asg_name_key,
        asg_tag_key,
        volume_type,
        volume_size,
        volume_iops,
        volume_throughput,
        ebs_device_name,
        block_device_name,
        filesystem_name,
        mount_directory_path,
    };
    command::execute(opts).await
}
