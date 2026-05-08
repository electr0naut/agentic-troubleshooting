from dataclasses import dataclass, field


@dataclass
class Finding:
    category: str   # cpu, memory, io, fd, network
    severity: str   # info, warning, critical
    message: str


@dataclass
class Report:
    host: str
    timestamp: str
    trigger: str
    cores: int = 0
    load_1m: float = 0.0
    load_5m: float = 0.0
    load_15m: float = 0.0
    mem_total: str = ""
    mem_used: str = ""
    mem_pct: float = 0.0
    pid: int = 0
    process_name: str = ""
    process_user: str = ""
    process_cpu: float = 0.0
    process_mem: float = 0.0
    process_state: str = ""
    open_files: int = 0
    file_limit: int = 0
    findings: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
