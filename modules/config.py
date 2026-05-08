import configparser
import os

SETTINGS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "settings.cfg"
)


def load_config(path=None):
    cfg = configparser.ConfigParser()
    cfg.read(path or SETTINGS_PATH)

    def g(section, key, fallback, cast=None):
        raw = cfg.get(section, key, fallback=str(fallback))
        return (cast or type(fallback))(raw)

    return {
        "command_timeout_secs":        g("timeouts", "command_timeout_secs", 10, int),
        "slow_command_timeout_secs":   g("timeouts", "slow_command_timeout_secs", 15, int),
        "investigation_budget_secs":   g("timeouts", "investigation_budget_secs", 300, int),
        "ssh_connect_timeout_secs":    g("timeouts", "ssh_connect_timeout_secs", 5, int),
        "log_lookback_minutes":        g("timeouts", "log_lookback_minutes", 10, int),
        "cpu_process_high_pct":        g("cpu", "process_high_pct", 50.0, float),
        "cpu_process_critical_pct":    g("cpu", "process_critical_pct", 95.0, float),
        "cpu_load_ratio_healthy":      g("cpu", "load_ratio_healthy", 0.7, float),
        "cpu_load_ratio_saturated":    g("cpu", "load_ratio_saturated", 1.0, float),
        "cpu_load_ratio_overloaded":   g("cpu", "load_ratio_overloaded", 2.0, float),
        "cpu_load_spike_multiplier":   g("cpu", "load_spike_multiplier", 1.5, float),
        "cpu_load_sustained_mult":     g("cpu", "load_sustained_multiplier", 1.3, float),
        "cpu_load_stable_tolerance":   g("cpu", "load_stable_tolerance", 0.2, float),
        "cpu_load_sustained_tol":      g("cpu", "load_sustained_tolerance", 0.3, float),
        "mem_process_high_pct":        g("memory", "process_high_pct", 50.0, float),
        "mem_rss_warning_mb":          g("memory", "process_rss_warning_mb", 100, int),
        "mem_vsz_rss_ratio_warning":   g("memory", "vsz_rss_ratio_warning", 10, int),
        "mem_vsz_absolute_warning_mb": g("memory", "vsz_absolute_warning_mb", 1000, int),
        "mem_swap_attribution_pct":    g("memory", "swap_attribution_min_pct", 5.0, float),
        "mem_compression_warning_mb":  g("memory", "compression_warning_mb", 2048, int),
        "mem_proc_swap_warning_mb":    g("memory", "process_swap_warning_mb", 100, int),
        "mem_rss_sample_interval":     g("memory", "rss_sample_interval_secs", 3, int),
        "mem_rss_sample_count":        g("memory", "rss_sample_count", 3, int),
        "mem_rss_growth_warning_pct":  g("memory", "rss_growth_warning_pct", 5.0, float),
        "io_reg_fd_ratio_warning":     g("io", "reg_fd_ratio_warning", 0.5, float),
        "io_reg_fd_count_min":         g("io", "reg_fd_count_min", 10, int),
        "io_iobound_cpu_max_pct":      g("io", "iobound_cpu_max_pct", 10.0, float),
        "io_iobound_cumtime_secs":     g("io", "iobound_cumulative_time_secs", 60, int),
        "io_disk_usage_critical_pct":  g("io", "disk_usage_critical_pct", 90, int),
        "fd_usage_ratio_warning":      g("fd", "usage_ratio_warning", 0.5, float),
        "fd_usage_ratio_critical":     g("fd", "usage_ratio_critical", 0.8, float),
        "fd_dir_leak_threshold":       g("fd", "dir_fd_leak_threshold", 20, int),
        "fd_pipe_warning":             g("fd", "pipe_fd_warning", 20, int),
        "fd_growth_active_leak":       g("fd", "growth_active_leak", 5, int),
        "fd_sample_interval":          g("fd", "fd_sample_interval_secs", 5, int),
        "fd_sample_count":             g("fd", "fd_sample_count", 3, int),
        "net_conn_count_warning":      g("network", "connection_count_warning", 50, int),
        "net_conn_count_critical":     g("network", "connection_count_critical", 200, int),
        "net_close_wait_warning":      g("network", "close_wait_warning", 5, int),
        "net_endpoint_conc_warning":   g("network", "endpoint_concentration_warning", 10, int),
        "net_display_max_conns":       g("network", "display_max_connections", 20, int),
        "out_top_process_count":       g("output", "top_process_count", 20, int),
        "out_top_thread_count":        g("output", "top_thread_count", 20, int),
        "out_max_reg_files":           g("output", "max_reg_files_shown", 30, int),
        "out_max_file_paths":          g("output", "max_file_paths_shown", 10, int),
        "out_max_dir_groups":          g("output", "max_dir_groups_shown", 3, int),
        "out_max_log_lines":           g("output", "max_log_lines", 20, int),
        "out_max_netstat_lines":       g("output", "max_netstat_lines", 100, int),
    }
