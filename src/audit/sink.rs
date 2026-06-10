use crate::audit::events::KernelFlowEvent;

pub trait AuditSink {
    fn emit(
        &mut self,
        event: &KernelFlowEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

#[derive(Default)]
pub struct JsonStdoutSink;

impl AuditSink for JsonStdoutSink {
    fn emit(
        &mut self,
        event: &KernelFlowEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("{}", serde_json::to_string(&event.to_audit_record())?);
        Ok(())
    }
}
