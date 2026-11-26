use super::*;

#[test]
fn job_lists_the_child_and_its_descendants() -> std::io::Result<()> {
    // The job object exists before the child, so assignment is the first
    // action after spawn. Two sequential pings make descendant capture
    // independent of the spawn/assign window: if cmd spawns the first ping
    // too early, the second one is spawned well after assignment and
    // inherits job membership.
    let job = Job::create().expect("creating a job object");
    let mut child = std::process::Command::new("cmd")
        .args(["/C", "ping -n 2 127.0.0.1 >NUL & ping -n 2 127.0.0.1 >NUL"])
        .spawn()?;
    assert!(job.assign(child.id()), "assigning the child to the job");
    let mut count = 0;
    for _ in 0..100 {
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
