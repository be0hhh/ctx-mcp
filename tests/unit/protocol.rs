use super::*;

fn request(op: &str) -> Json {
    Json::obj(vec![("op", Json::Str(op.to_string()))])
}

#[test]
fn subprocess_semaphore_releases_capacity_and_never_grants_after_deadline() {
    let sem = SubprocSemaphore::new(1);
    let permit = sem.acquire(Duration::from_secs(1)).unwrap();
    thread::scope(|scope| {
        let waiter = scope.spawn(|| sem.acquire(Duration::from_secs(1)));
        assert!(sem.acquire_until(Instant::now()).unwrap().is_none());
        assert_eq!(sem.active_count(), 1);
        drop(permit);
        assert!(waiter.join().unwrap().is_ok());
    });
    assert_eq!(sem.active_count(), 0);
    assert_eq!(sem.peak_count(), 1);
}

#[test]
fn transport_never_degrades_search_to_inproc() {
    let search = request("search");
    assert_eq!(
        run_inproc(&search).get_str("code"),
        Some("daemon_unavailable")
    );

    let after_send = complete_attempt(SendOutcome::AfterSend, &search).unwrap();
    assert_eq!(after_send.get_str("code"), Some("daemon_transport"));
    assert_eq!(after_send.get_bool("retryable"), Some(false));

    let rejected = complete_attempt(SendOutcome::Busy, &search).unwrap();
    assert_eq!(rejected.get_str("code"), Some("daemon_busy"));
    assert_eq!(rejected.get_bool("retryable"), Some(true));
}

#[test]
fn lost_confirmation_is_unknown_for_mutations_and_scoped_reads() {
    let memo = Json::obj(vec![
        ("op", Json::Str("memo".to_string())),
        ("action", Json::Str("put".to_string())),
    ]);
    let scoped = Json::obj(vec![
        ("op", Json::Str("read".to_string())),
        ("ctx_context", Json::Str("ticket".to_string())),
    ]);
    assert_eq!(
        run_inproc(&scoped).get_str("code"),
        Some("daemon_unavailable")
    );
    assert_eq!(
        run_inproc(&request("capsule")).get_str("code"),
        Some("daemon_unavailable")
    );
    for req in [request("capsule"), request("hook"), memo, scoped] {
        let lost = complete_attempt(SendOutcome::AfterSend, &req).unwrap();
        assert_eq!(lost.get_str("code"), Some("outcome_unknown"));
        assert_eq!(lost.get_bool("retryable"), Some(false));
    }

    let independent = complete_attempt(SendOutcome::AfterSend, &request("status")).unwrap();
    assert_eq!(independent.get_bool("degraded_inproc"), Some(true));
}
