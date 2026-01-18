#[repr(C)]
#[derive(Debug)]
pub struct TelemetryEntry {
    pub uuid: uuid::Uuid,
    pub nt_function: NtFunction,
    pub args: Args,
    pub pid: u32,
    /// Time of the telemetry object being created
    pub time: i64,
}

#[repr(C)]
#[derive(Debug)]
pub enum NtFunction {
    NtOpenProcess,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct Args {
    pub rcx: Option<usize>,
    pub rdx: Option<usize>,
    pub r8: Option<usize>,
    pub r9: Option<usize>,
    pub stack1: Option<usize>,
    pub stack2: Option<usize>,
    pub stack3: Option<usize>,
    pub stack4: Option<usize>,
    pub stack5: Option<usize>,
    pub stack6: Option<usize>,
    pub stack7: Option<usize>,
}