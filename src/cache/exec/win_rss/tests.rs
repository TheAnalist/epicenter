use super::*;

#[test]
fn job_lists_the_child_and_its_descendants() -> std::io::Result<()> {
    let mut child = std::process::Command::new("cmd")
        .args(["/C", "ping -n 2 127.0.0.1 >NUL"])
        .spawn()?;
    let job = Job::create(child.id()).expect("assigning the child to a job");
    let mut count = 0;
    for _ in 0..10 {
        let mut list: ProcessIdList = unsafe { std::mem::zeroed() };
        count = job_pids(job.0, &mut list).unwrap_or(0);
        if count >= 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let status = child.wait()?;
    assert!(status.success());
    assert!(count >= 2, "job members: {count}");
    Ok(())
}
