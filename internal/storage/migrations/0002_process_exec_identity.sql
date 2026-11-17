-- A PID can successfully exec more than once without creating a new process,
-- and Linux audit timestamps have only millisecond precision. The original
-- boot/PID/start-time uniqueness rule therefore rejected distinct exec
-- observations that happened in the same millisecond. Keep lookup ordering in
-- the existing non-unique processes_pid_idx and scope uniqueness to a concrete
-- collector execution identity when one is available.
DROP INDEX IF EXISTS processes_identity_idx;

CREATE UNIQUE INDEX processes_execution_identity_idx
    ON processes(boot_id, pid, start_time_ns, exec_id)
    WHERE boot_id <> '' AND start_time_ns > 0 AND exec_id <> '';
