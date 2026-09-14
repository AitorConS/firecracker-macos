// SPDX-License-Identifier: Apache-2.0
//! Bounded operation history; completed diagnostics survive subsequent requests.
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

#[derive(Serialize)]
pub(super) struct Operation {
    pub id: u64,
    action: String,
    status: &'static str,
    elapsed_ms: u128,
    result: Option<Value>,
    #[serde(skip)]
    started: Instant,
}
#[derive(Default)]
struct Totals {
    completed: u64,
    failed: u64,
    cancelled: u64,
    seconds: f64,
    last_seconds: f64,
}
#[derive(Default)]
pub(super) struct Operations {
    recent: VecDeque<Operation>,
    next: u64,
    totals: BTreeMap<String, Totals>,
}
impl Operations {
    pub fn begin(&mut self, action: &str) -> u64 {
        self.finish("cancelled", Some(serde_json::json!({"fault_code":"SUPERSEDED","fault_message":"cancelled by ForceStop"})));
        self.next += 1;
        if self.recent.len() == 64 {
            self.recent.pop_front();
        }
        self.recent.push_back(Operation {
            id: self.next,
            action: action.into(),
            status: "pending",
            elapsed_ms: 0,
            result: None,
            started: Instant::now(),
        });
        self.next
    }
    pub fn finish(&mut self, status: &'static str, result: Option<Value>) {
        if let Some(op) = self.recent.back_mut()
            && op.status == "pending"
        {
            op.status = status;
            op.elapsed_ms = op.started.elapsed().as_millis();
            op.result = result;
            let total = self.totals.entry(op.action.clone()).or_default();
            total.completed += 1;
            total.failed += u64::from(status == "failed");
            total.cancelled += u64::from(status == "cancelled");
            total.last_seconds = op.started.elapsed().as_secs_f64();
            total.seconds += total.last_seconds;
        }
    }
    pub fn metrics(&self, value: &mut Value) {
        value["operation_pending_seconds"] = serde_json::json!(
            self.recent
                .back()
                .filter(|op| op.status == "pending")
                .map(|op| op.started.elapsed().as_secs_f64())
                .unwrap_or(0.0)
        );
        for (action, total) in &self.totals {
            let name = action.to_ascii_lowercase();
            value[format!("operation_{name}_completed_total")] = serde_json::json!(total.completed);
            value[format!("operation_{name}_failed_total")] = serde_json::json!(total.failed);
            value[format!("operation_{name}_cancelled_total")] = serde_json::json!(total.cancelled);
            value[format!("operation_{name}_duration_seconds_total")] =
                serde_json::json!(total.seconds);
            value[format!("operation_{name}_last_duration_seconds")] =
                serde_json::json!(total.last_seconds);
        }
    }
    pub fn expects_forced_exit(&self) -> bool {
        self.recent
            .back()
            .is_some_and(|op| op.action == "ForceStop")
    }
    pub fn exited(&mut self, success: bool, exit_code: Option<i32>) {
        let expected = self.expects_forced_exit();
        self.finish(
            if success || expected {
                "succeeded"
            } else {
                "failed"
            },
            Some(serde_json::json!({"exit_code": exit_code})),
        );
    }
    pub fn get(&self, id: u64) -> Option<&Operation> {
        self.recent.iter().find(|op| op.id == id)
    }
    pub fn list(&self) -> &VecDeque<Operation> {
        &self.recent
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_and_retention() {
        let mut ops = Operations::default();
        let first = ops.begin("InstanceStart");
        ops.begin("ForceStop");
        assert_eq!(ops.get(first).unwrap().status, "cancelled");
        ops.finish("succeeded", None);
        for _ in 0..64 {
            ops.begin("InstanceStart");
            ops.finish("failed", None);
        }
        assert_eq!(ops.list().len(), 64);
        assert!(ops.get(first).is_none());
    }
}
