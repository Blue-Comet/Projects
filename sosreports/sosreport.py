#!/usr/bin/env python3
"""
SOSReport Automated Analyzer & HTML Report Generator
Usage:
    python3 sosreport.py sourcefile outputfile
"""

import sys
import os
import re
import json
import tarfile
import argparse
import datetime
from pathlib import Path


def find_default_archive(search_dirs=None):
    """Auto-detect sosreport tar.xz / tar.gz archive in common paths."""
    if search_dirs is None:
        script_dir = Path(__file__).resolve().parent
        search_dirs = [
            script_dir / "Files",
            script_dir,
            Path.cwd() / "Files",
            Path.cwd(),
            script_dir.parent / "Files",
            Path("/home/comet/문서/GitHub/Projects/sosreports/Files"),
        ]

    patterns = ["sosreport*.tar.xz", "sosreport*.tar.gz", "sosreport*.tar", "*.tar.xz"]

    for sdir in search_dirs:
        if not sdir.exists() or not sdir.is_dir():
            continue
        for pat in patterns:
            matches = sorted(sdir.glob(pat), key=lambda p: p.stat().st_mtime, reverse=True)
            if matches:
                return str(matches[0])
    return None


class SOSReportParser:
    def __init__(self, archive_path):
        self.archive_path = Path(archive_path).resolve()
        if not self.archive_path.exists():
            raise FileNotFoundError(f"SOSReport archive not found: {self.archive_path}")
        self.raw_files = {}
        self.data = {
            "archive_name": self.archive_path.name,
            "archive_size_mb": round(self.archive_path.stat().st_size / (1024 * 1024), 2),
            "manifest": {},
            "system": {},
            "aws": {},
            "cpu": {},
            "memory": {},
            "disks": [],
            "block_devices": {"all": [], "local_disks": [], "additional_disks": []},
            "users": [],
            "ssh_config": {},
            "timers": [],
            "crontabs": {"user_jobs": [], "system_jobs": [], "all_jobs": [], "periodic": {}},
            "sysctl": {},
            "dns": {},
            "log_audit": {"oom_count": 0, "segfault_count": 0, "io_error_count": 0},
            "failed_units": [],
            "blame": [],
            "network": {"interfaces": [], "routes": [], "listening_ports": [], "connections": []},
            "processes": {"top_cpu": [], "top_mem": [], "all": []},
            "dmesg_issues": [],
            "journal_issues": [],
            "logins": [],
            "nginx": {},
            "health_score": 100,
            "findings": [],
            "source_paths": {},
        }

    def extract_needed_files(self):
        """Read target diagnostic files directly from the archive in memory, resolving symlinks and recording source paths."""
        print(f"[*] Reading archive: {self.archive_path.name} ({self.data['archive_size_mb']} MB)...")

        with tarfile.open(self.archive_path, "r:*") as tar:
            all_members = tar.getmembers()
            member_map = {m.name: m for m in all_members}
            prefix = all_members[0].name.split("/")[0]

            def resolve_member(m):
                visited = set()
                curr = m
                while curr and curr.issym():
                    visited.add(curr.name)
                    tgt = curr.linkname if curr.linkname.startswith(prefix) else f"{prefix}/{curr.linkname}"
                    if tgt in visited:
                        break
                    curr = member_map.get(tgt)
                return curr

            target_map = {
                "df": ["df", "sos_commands/filesys/df_-al_-x_autofs", "sos_commands/filesys/df"],
                "df_inodes": ["sos_commands/filesys/df_-aliT_-x_autofs"],
                "lsblk": ["sos_commands/block/lsblk", "lsblk", "sos_commands/block/lsblk_-f_-a_-l"],
                "getent_passwd": ["sos_commands/getent/getent_passwd", "etc/passwd"],
                "getent_group": ["sos_commands/getent/getent_group", "etc/group"],
                "sudoers": ["etc/sudoers"],
                "lslogins": ["sos_commands/login/lslogins"],
                "sshd_-T": ["sos_commands/ssh/sshd_-T"],
                "timers": ["sos_commands/systemd/systemctl_list-timers_--all"],
                "crontab": ["etc/crontab", "crontab"],
                "root_crontab": ["sos_commands/cron/root_crontab"],
                "sysctl": ["sos_commands/kernel/sysctl_-a"],
                "resolvectl": ["sos_commands/systemd/resolvectl_status"],
                "ip_addr": ["ip_addr", "sos_commands/networking/ip_-o_addr", "sos_commands/networking/ip_addr"],
                "ip_route": ["ip_route", "sos_commands/networking/ip_route"],
                "netstat": ["netstat", "sos_commands/networking/netstat_-W_-neopa", "sos_commands/networking/netstat"],
                "ps": ["ps", "sos_commands/process/ps_auxwwwm", "sos_commands/process/ps_-elfL"],
                "free": ["free", "sos_commands/memory/free"],
                "meminfo": ["proc/meminfo", "meminfo", "sos_commands/memory/meminfo"],
                "uptime": ["uptime", "sos_commands/host/uptime"],
                "lscpu": ["sos_commands/processor/lscpu", "lscpu"],
                "cpuinfo": ["proc/cpuinfo", "cpuinfo", "sos_commands/processor/cpuinfo"],
                "hostname": ["hostname", "sos_commands/host/hostname"],
                "uname": ["uname", "sos_commands/kernel/uname_-a", "sos_commands/kernel/uname"],
                "date": ["date", "sos_commands/date/date"],
                "lsb-release": ["lsb-release", "etc/lsb-release", "etc/os-release"],
                "os-release": ["os-release", "etc/os-release"],
                "manifest.json": ["sos_reports/manifest.json", "manifest.json"],
                "version.txt": ["version.txt", "sos_reports/version.txt"],
                "systemctl_list-units_--failed": ["sos_commands/systemd/systemctl_list-units_--failed"],
                "systemctl_status_--all": ["sos_commands/systemd/systemctl_status_--all"],
                "systemd-analyze_blame": ["sos_commands/systemd/systemd-analyze_blame"],
                "dmesg": ["sos_commands/kernel/dmesg", "dmesg", "dmesg_-T"],
                "journalctl_--no-pager_--boot": ["sos_commands/logs/journalctl_--no-pager_--boot"],
                "last": ["last", "sos_commands/login/last_-F", "sos_commands/login/last"],
                "nginx_-V": ["sos_commands/nginx/nginx_-V"],
                "aws_metadata_instance-id.txt": ["sos_commands/aws/aws_metadata_instance-id.txt"],
                "aws_metadata_instance-type.txt": ["sos_commands/aws/aws_metadata_instance-type.txt"],
                "aws_metadata_placement_availability-zone-id.txt": ["sos_commands/aws/aws_metadata_placement_availability-zone-id.txt"],
                "aws_metadata_hostname.txt": ["sos_commands/aws/aws_metadata_hostname.txt"],
            }

            for key, candidates in target_map.items():
                for cand in candidates:
                    full_cand = f"{prefix}/{cand}" if not cand.startswith(prefix) else cand
                    m = member_map.get(full_cand)
                    if m:
                        m_real = resolve_member(m)
                        if m_real and m_real.isfile():
                            try:
                                content = tar.extractfile(m_real).read().decode("utf-8", errors="replace")
                                if content:
                                    self.raw_files[key] = content
                                    rel_src = m_real.name[len(prefix)+1:] if m_real.name.startswith(prefix + "/") else m_real.name
                                    self.data["source_paths"][key] = rel_src
                                    break
                            except Exception as e:
                                print(f"[!] Warning reading {m_real.name}: {e}")

            # Extract all files under etc/sudoers.d/
            sudoers_d_files = {}
            for m in all_members:
                if "etc/sudoers.d" in m.name and not m.name.endswith("README"):
                    m_real = resolve_member(m)
                    if m_real and m_real.isfile():
                        try:
                            content = tar.extractfile(m_real).read().decode("utf-8", errors="replace")
                            if content:
                                bname = m_real.name.split("/")[-1]
                                sudoers_d_files[bname] = content
                        except Exception:
                            pass
            self.raw_files["sudoers_d"] = sudoers_d_files
            if sudoers_d_files:
                self.data["source_paths"]["sudoers_d"] = "etc/sudoers.d/*"

            # Extract user crontabs, system cron.d, and periodic cron directories
            user_crontabs = {}
            for m in all_members:
                if ("var/spool/cron/crontabs/" in m.name or "var/spool/cron/" in m.name) and not m.isdir():
                    m_real = resolve_member(m)
                    if m_real and m_real.isfile():
                        bname = m_real.name.split("/")[-1]
                        if bname and not bname.startswith(".") and bname != "crontabs":
                            try:
                                content = tar.extractfile(m_real).read().decode("utf-8", errors="replace")
                                if content:
                                    rel_src = m_real.name[len(prefix)+1:] if m_real.name.startswith(prefix + "/") else m_real.name
                                    user_crontabs[bname] = {"content": content, "source": rel_src}
                            except Exception:
                                pass
            self.raw_files["user_crontabs"] = user_crontabs

            cron_d_files = {}
            for m in all_members:
                if "etc/cron.d/" in m.name and not m.isdir():
                    m_real = resolve_member(m)
                    if m_real and m_real.isfile():
                        bname = m_real.name.split("/")[-1]
                        if bname and not bname.startswith(".") and not bname.endswith("README") and not bname.endswith(".placeholder"):
                            try:
                                content = tar.extractfile(m_real).read().decode("utf-8", errors="replace")
                                if content:
                                    rel_src = m_real.name[len(prefix)+1:] if m_real.name.startswith(prefix + "/") else m_real.name
                                    cron_d_files[bname] = {"content": content, "source": rel_src}
                            except Exception:
                                pass
            self.raw_files["cron_d"] = cron_d_files

            cron_periodic = {"hourly": [], "daily": [], "weekly": [], "monthly": []}
            for period in ["hourly", "daily", "weekly", "monthly"]:
                target_dir = f"etc/cron.{period}/"
                for m in all_members:
                    if target_dir in m.name and not m.isdir():
                        m_real = resolve_member(m)
                        if m_real and m_real.isfile():
                            bname = m_real.name.split("/")[-1]
                            if bname and not bname.startswith(".") and not bname.endswith(".placeholder"):
                                cron_periodic[period].append(bname)
                cron_periodic[period].sort()
            self.raw_files["cron_periodic"] = cron_periodic

            self.data["source_paths"]["crontabs"] = "etc/crontab, var/spool/cron/crontabs/*, etc/cron.d/*"

        print(f"[+] Loaded {len(self.raw_files)} diagnostic command outputs with symlinks resolved.")

    def parse_all(self):
        self._parse_manifest()
        self._parse_system_info()
        self._parse_aws()
        self._parse_cpu()
        self._parse_memory()
        self._parse_disks()
        self._parse_users()
        self._parse_ssh()
        self._parse_services()
        self._parse_timers()
        self._parse_crontabs()
        self._parse_network()
        self._parse_sysctl_and_dns()
        self._parse_processes()
        self._parse_logs()
        self._parse_security_and_apps()
        self._evaluate_health()

    def _parse_manifest(self):
        content = self.raw_files.get("manifest.json")
        if content:
            try:
                full_m = json.loads(content)
                self.data["manifest"] = {
                    "version": full_m.get("version", "N/A"),
                    "cmdline": full_m.get("cmdline", "N/A"),
                    "start_time": full_m.get("start_time", "N/A"),
                    "end_time": full_m.get("end_time", "N/A"),
                    "run_time": full_m.get("run_time", "N/A"),
                    "policy": full_m.get("policy", "N/A"),
                }
            except Exception:
                pass

    def _parse_system_info(self):
        self.data["system"]["hostname"] = self.raw_files.get("hostname", "").strip() or "Unknown"
        self.data["system"]["uname"] = self.raw_files.get("uname", "").strip()
        self.data["system"]["date"] = self.raw_files.get("date", "").strip()
        
        # OS release
        os_text = self.raw_files.get("lsb-release") or self.raw_files.get("os-release", "")
        distro = "Linux"
        for line in os_text.splitlines():
            if line.startswith("DISTRIB_DESCRIPTION="):
                distro = line.split("=", 1)[1].strip('"\'')
                break
            elif line.startswith("PRETTY_NAME="):
                distro = line.split("=", 1)[1].strip('"\'')
        self.data["system"]["os_distro"] = distro

        # Kernel
        uname_parts = self.data["system"]["uname"].split()
        if len(uname_parts) >= 3:
            self.data["system"]["kernel"] = uname_parts[2]
            self.data["system"]["arch"] = uname_parts[-2] if len(uname_parts) > 3 else "x86_64"
        else:
            self.data["system"]["kernel"] = "Unknown"
            self.data["system"]["arch"] = "Unknown"

        # Uptime & Load
        uptime_str = self.raw_files.get("uptime", "").strip()
        self.data["system"]["raw_uptime"] = uptime_str
        load_match = re.search(r"load average:\s*([\d\.]+),\s*([\d\.]+),\s*([\d\.]+)", uptime_str)
        if load_match:
            self.data["system"]["load_1m"] = float(load_match.group(1))
            self.data["system"]["load_5m"] = float(load_match.group(2))
            self.data["system"]["load_15m"] = float(load_match.group(3))
        else:
            self.data["system"]["load_1m"] = self.data["system"]["load_5m"] = self.data["system"]["load_15m"] = 0.0

        up_match = re.search(r"up\s+(.*?),\s+\d+\s+users?", uptime_str)
        self.data["system"]["uptime_human"] = up_match.group(1).strip() if up_match else "Unknown"

    def _parse_aws(self):
        iid = self.raw_files.get("aws_metadata_instance-id.txt", "").strip()
        itype = self.raw_files.get("aws_metadata_instance-type.txt", "").strip()
        az = self.raw_files.get("aws_metadata_placement_availability-zone-id.txt", "").strip()
        kernel = self.data["system"].get("kernel", "").lower()
        dmesg_text = self.raw_files.get("dmesg", "")
        is_aws = bool(iid or itype or "-aws" in kernel or "amazon ec2" in dmesg_text.lower() or "amazon" in self.data["system"].get("os_distro", "").lower())
        if is_aws:
            self.data["aws"] = {
                "is_ec2": True,
                "instance_id": iid or "N/A",
                "instance_type": itype or "AWS EC2",
                "availability_zone": az or "N/A",
            }
        else:
            self.data["aws"] = {"is_ec2": False}

    def _parse_cpu(self):
        lscpu = self.raw_files.get("lscpu", "")
        cpu_info = {}
        for line in lscpu.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                cpu_info[k.strip()] = v.strip()
        
        # Parse proc/cpuinfo
        cpuinfo_text = self.raw_files.get("cpuinfo", "")
        cpuinfo_cores = []
        curr_core = {}
        for line in cpuinfo_text.splitlines():
            line_s = line.strip()
            if not line_s:
                if curr_core:
                    cpuinfo_cores.append(curr_core)
                    curr_core = {}
                continue
            if ":" in line_s:
                k, v = line_s.split(":", 1)
                curr_core[k.strip()] = v.strip()
        if curr_core:
            cpuinfo_cores.append(curr_core)

        first_core = cpuinfo_cores[0] if cpuinfo_cores else {}
        flags_list = first_core.get("flags", "").split()
        bugs_list = first_core.get("bugs", "").split()

        self.data["cpu"] = {
            "model": cpu_info.get("Model name", first_core.get("model name", "Unknown CPU")),
            "cores": int(cpu_info.get("CPU(s)", len(cpuinfo_cores) or 1)),
            "threads_per_core": cpu_info.get("Thread(s) per core", "1"),
            "architecture": cpu_info.get("Architecture", self.data["system"].get("arch", "x86_64")),
            "mhz": cpu_info.get("CPU MHz", first_core.get("cpu MHz", "N/A")),
            "raw": cpu_info,
            "cpuinfo": {
                "logical_cpus": len(cpuinfo_cores),
                "vendor_id": first_core.get("vendor_id", "N/A"),
                "family": first_core.get("cpu family", "N/A"),
                "model": first_core.get("model", "N/A"),
                "stepping": first_core.get("stepping", "N/A"),
                "microcode": first_core.get("microcode", "N/A"),
                "cache_size": first_core.get("cache size", "N/A"),
                "bogomips": first_core.get("bogomips", "N/A"),
                "address_sizes": first_core.get("address sizes", "N/A"),
                "flags": flags_list,
                "bugs": bugs_list,
                "virtualization": [f for f in ["vmx", "svm", "hypervisor"] if f in flags_list],
                "simd": [f for f in ["sse4_1", "sse4_2", "avx", "avx2", "avx512f", "avx512dq", "avx512bw", "avx512vl", "fma"] if f in flags_list],
                "crypto_security": [f for f in ["aes", "rdrand", "rdseed", "smep", "smap", "pti"] if f in flags_list],
            }
        }

    def _parse_memory(self):
        free_text = self.raw_files.get("free", "")
        mem_data = {
            "total_mb": 0, "used_mb": 0, "free_mb": 0,
            "buff_cache_mb": 0, "available_mb": 0,
            "swap_total_mb": 0, "swap_used_mb": 0, "swap_free_mb": 0,
            "usage_pct": 0, "swap_usage_pct": 0
        }
        for line in free_text.splitlines():
            parts = line.split()
            if line.startswith("Mem:") and len(parts) >= 7:
                try:
                    total = float(parts[1]) / 1024
                    used = float(parts[2]) / 1024
                    free = float(parts[3]) / 1024
                    shared = float(parts[4]) / 1024
                    buff = float(parts[5]) / 1024
                    avail = float(parts[6]) / 1024
                    mem_data["total_mb"] = round(total, 1)
                    mem_data["used_mb"] = round(used, 1)
                    mem_data["free_mb"] = round(free, 1)
                    mem_data["buff_cache_mb"] = round(buff, 1)
                    mem_data["available_mb"] = round(avail, 1)
                    if total > 0:
                        mem_data["usage_pct"] = round(((total - avail) / total) * 100, 1)
                except ValueError:
                    pass
            elif line.startswith("Swap:") and len(parts) >= 4:
                try:
                    s_total = float(parts[1]) / 1024
                    s_used = float(parts[2]) / 1024
                    s_free = float(parts[3]) / 1024
                    mem_data["swap_total_mb"] = round(s_total, 1)
                    mem_data["swap_used_mb"] = round(s_used, 1)
                    mem_data["swap_free_mb"] = round(s_free, 1)
                    if s_total > 0:
                        mem_data["swap_usage_pct"] = round((s_used / s_total) * 100, 1)
                except ValueError:
                    pass

        # Parse proc/meminfo
        meminfo_text = self.raw_files.get("meminfo", "")
        meminfo_dict = {}
        for line in meminfo_text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                v_parts = v.strip().split()
                if v_parts and v_parts[0].isdigit():
                    meminfo_dict[k.strip()] = int(v_parts[0])

        total_kb = meminfo_dict.get("MemTotal", int(mem_data["total_mb"] * 1024))
        avail_kb = meminfo_dict.get("MemAvailable", int(mem_data["available_mb"] * 1024))
        free_kb = meminfo_dict.get("MemFree", int(mem_data["free_mb"] * 1024))
        committed_as_kb = meminfo_dict.get("Committed_AS", 0)
        commit_limit_kb = meminfo_dict.get("CommitLimit", 0)
        commit_ratio = round((committed_as_kb / max(1, commit_limit_kb)) * 100, 1)

        mem_data["meminfo"] = {
            "total_kb": total_kb,
            "free_kb": free_kb,
            "available_kb": avail_kb,
            "cached_kb": meminfo_dict.get("Cached", 0),
            "buffers_kb": meminfo_dict.get("Buffers", 0),
            "slab_kb": meminfo_dict.get("Slab", 0),
            "s_reclaimable_kb": meminfo_dict.get("SReclaimable", 0),
            "s_unreclaim_kb": meminfo_dict.get("SUnreclaim", 0),
            "active_anon_kb": meminfo_dict.get("Active(anon)", 0),
            "inactive_anon_kb": meminfo_dict.get("Inactive(anon)", 0),
            "active_file_kb": meminfo_dict.get("Active(file)", 0),
            "inactive_file_kb": meminfo_dict.get("Inactive(file)", 0),
            "dirty_kb": meminfo_dict.get("Dirty", 0),
            "writeback_kb": meminfo_dict.get("Writeback", 0),
            "page_tables_kb": meminfo_dict.get("PageTables", 0),
            "kernel_stack_kb": meminfo_dict.get("KernelStack", 0),
            "committed_as_kb": committed_as_kb,
            "commit_limit_kb": commit_limit_kb,
            "commit_ratio_pct": commit_ratio,
            "hugepagesize_kb": meminfo_dict.get("Hugepagesize", 0),
            "hugepages_total": meminfo_dict.get("HugePages_Total", 0),
            "hugepages_free": meminfo_dict.get("HugePages_Free", 0),
            "raw": meminfo_dict
        }
        self.data["memory"] = mem_data

    def _parse_disks(self):
        inode_text = self.raw_files.get("df_inodes", "")
        inode_map = {}
        for line in inode_text.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 7:
                mount = " ".join(parts[6:])
                inode_map[mount] = {
                    "inodes": parts[2],
                    "iused": parts[3],
                    "ifree": parts[4],
                    "iuse_pct": parts[5]
                }

        df_text = self.raw_files.get("df", "")
        lines = df_text.strip().splitlines()
        disks = []
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    fs = parts[0]
                    total = parts[1]
                    used = parts[2]
                    avail = parts[3]
                    pct = parts[4]
                    mount = " ".join(parts[5:])
                    try:
                        tot_gb = float(total) / (1024 * 1024)
                        used_gb = float(used) / (1024 * 1024)
                        avail_gb = float(avail) / (1024 * 1024)
                        tot_str = f"{tot_gb:.1f} GB" if tot_gb >= 1 else f"{float(total)/1024:.0f} MB"
                        used_str = f"{used_gb:.1f} GB" if used_gb >= 1 else f"{float(used)/1024:.0f} MB"
                        avail_str = f"{avail_gb:.1f} GB" if avail_gb >= 1 else f"{float(avail)/1024:.0f} MB"
                    except Exception:
                        tot_str, used_str, avail_str = total, used, avail
                    
                    pct_num = int(pct.replace("%", "")) if "%" in pct and pct.replace("%", "").isdigit() else 0
                    is_real = fs.startswith("/dev/")
                    im = inode_map.get(mount, {})
                    iuse_pct_str = im.get("iuse_pct", "-")
                    iuse_num = int(iuse_pct_str.replace("%", "")) if "%" in iuse_pct_str and iuse_pct_str.replace("%", "").isdigit() else 0

                    disks.append({
                        "filesystem": fs,
                        "mount": mount,
                        "size": tot_str,
                        "used": used_str,
                        "avail": avail_str,
                        "pct": pct,
                        "pct_num": pct_num,
                        "inodes": im.get("inodes", "-"),
                        "iused": im.get("iused", "-"),
                        "iuse_pct": iuse_pct_str,
                        "iuse_num": iuse_num,
                        "is_real_device": is_real
                    })
        # Sort real devices first, then highest usage
        disks.sort(key=lambda d: (not d["is_real_device"], -d["pct_num"]))
        self.data["disks"] = disks

        # Parse block devices (lsblk)
        lsblk_text = self.raw_files.get("lsblk", "")
        block_disks = []
        current_disk = None
        for line in lsblk_text.strip().splitlines()[1:]:
            parts = line.split()
            if not parts:
                continue
            name_col = parts[0]
            is_part = name_col.startswith("├─") or name_col.startswith("└─") or name_col.startswith("|-") or name_col.startswith("`-") or "part" in parts
            clean_name = name_col.replace("├─", "").replace("└─", "").replace("|-", "").replace("`-", "").strip()
            size = parts[3] if len(parts) > 3 else "N/A"
            dev_type = parts[5] if len(parts) > 5 else ("part" if is_part else "disk")
            mount = " ".join(parts[6:]) if len(parts) > 6 else ""

            if not is_part and dev_type == "disk":
                current_disk = {
                    "name": clean_name,
                    "device": f"/dev/{clean_name}",
                    "size": size,
                    "type": dev_type,
                    "mount": mount,
                    "partitions": [],
                    "is_root": (mount == "/")
                }
                block_disks.append(current_disk)
            else:
                part_info = {
                    "name": clean_name,
                    "device": f"/dev/{clean_name}",
                    "size": size,
                    "type": dev_type,
                    "mount": mount
                }
                if mount == "/":
                    if current_disk:
                        current_disk["is_root"] = True
                if current_disk:
                    current_disk["partitions"].append(part_info)

        local_disks = [d for d in block_disks if d.get("is_root")]
        additional_disks = [d for d in block_disks if not d.get("is_root")]
        self.data["block_devices"] = {
            "all": block_disks,
            "local_disks": local_disks,
            "additional_disks": additional_disks
        }

    def _parse_users(self):
        # 1. Parse groups for sudoers (%sudo, %wheel, %admin)
        group_content = self.raw_files.get("getent_group", "")
        sudo_users = {}
        for line in group_content.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 4 and parts[0] in ("sudo", "wheel", "admin"):
                grp_name = parts[0]
                members = parts[3].split(",")
                for u in members:
                    u = u.strip()
                    if u:
                        sudo_users[u] = f"%{grp_name} ALL=(ALL:ALL) ALL"

        # 2. Parse /etc/sudoers and /etc/sudoers.d/*
        sudo_sources = [self.raw_files.get("sudoers", "")]
        sudo_sources.extend(self.raw_files.get("sudoers_d", {}).values())

        for src_text in sudo_sources:
            for line in src_text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("Defaults") or line.startswith("@include"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    tgt = parts[0].strip()
                    rule = parts[1].strip()
                    if not tgt.startswith("%"):
                        sudo_users[tgt] = rule

        # 3. Logins
        logins_content = self.raw_files.get("lslogins", "")
        login_meta = {}
        for line in logins_content.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6 and parts[0].isdigit():
                user = parts[1]
                proc = parts[2]
                pwd_lock = parts[3]
                pwd_deny = parts[4]
                last_login = parts[5]
                login_meta[user] = {
                    "proc": proc,
                    "pwd_lock": pwd_lock,
                    "pwd_deny": pwd_deny,
                    "last_login": last_login
                }

        passwd_content = self.raw_files.get("getent_passwd", "")
        users = []
        for line in passwd_content.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 7:
                user, pwd, uid, gid, gecos, home, shell = parts[:7]
                uid_int = int(uid) if uid.isdigit() else 9999
                gid_int = int(gid) if gid.isdigit() else 9999
                meta = login_meta.get(user, {})
                
                is_interactive = not (shell.endswith("nologin") or shell.endswith("false") or shell == "/bin/sync")
                is_regular = (uid_int == 0) or (1000 <= uid_int < 65534)
                
                has_sudo = (user in sudo_users) or (uid_int == 0)
                sudo_rule = sudo_users.get(user, "Superuser (Root)" if uid_int == 0 else "")

                users.append({
                    "username": user,
                    "uid": uid_int,
                    "gid": gid_int,
                    "gecos": gecos.strip(","),
                    "home": home,
                    "shell": shell,
                    "is_interactive": is_interactive,
                    "is_regular": is_regular,
                    "has_sudo": has_sudo,
                    "sudo_rule": sudo_rule,
                    "proc_count": meta.get("proc", "0"),
                    "last_login": meta.get("last_login", "-")
                })

        users.sort(key=lambda u: (not u["has_sudo"], not u["is_regular"], not u["is_interactive"], u["uid"]))
        self.data["users"] = users

    def _parse_ssh(self):
        ssh_text = self.raw_files.get("sshd_-T", "")
        cfg = {}
        for line in ssh_text.splitlines():
            line_s = line.strip()
            if not line_s or line_s.startswith("#"):
                continue
            parts = line_s.split(None, 1)
            if len(parts) == 2:
                k, v = parts[0].lower(), parts[1].strip()
                if k not in cfg:
                    cfg[k] = v
        self.data["ssh_config"] = {
            "port": cfg.get("port", "22"),
            "passwordauthentication": cfg.get("passwordauthentication", "unknown"),
            "pubkeyauthentication": cfg.get("pubkeyauthentication", "unknown"),
            "permitrootlogin": cfg.get("permitrootlogin", "unknown"),
            "maxauthtries": cfg.get("maxauthtries", "6"),
            "clientaliveinterval": cfg.get("clientaliveinterval", "0"),
            "x11forwarding": cfg.get("x11forwarding", "no"),
            "raw": cfg
        }

    def _parse_services(self):
        # Failed units
        failed_text = self.raw_files.get("systemctl_list-units_--failed", "")
        status_all = self.raw_files.get("systemctl_status_--all", "")
        failed_units = []

        for line in failed_text.splitlines():
            line_s = line.strip()
            if line_s.startswith("●"):
                parts = line_s.split(None, 4)
                if len(parts) >= 5:
                    unit_name = parts[1]
                    if "motd" in unit_name.lower():
                        continue
                    desc = parts[4]
                    detail_log = ""
                    # Search detail from status_all
                    if unit_name in status_all:
                        chunks = status_all.split("● ")
                        for ch in chunks:
                            if ch.startswith(unit_name):
                                detail_log = ch.strip()[:1200]
                                break
                    failed_units.append({
                        "unit": unit_name,
                        "load": parts[2],
                        "active": parts[3],
                        "sub": parts[3],
                        "desc": desc,
                        "log": detail_log
                    })
        self.data["failed_units"] = failed_units

        # Boot blame
        blame_text = self.raw_files.get("systemd-analyze_blame", "")
        blame_list = []
        for line in blame_text.splitlines()[:15]:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                if "motd" in parts[1].lower():
                    continue
                blame_list.append({"time": parts[0], "service": parts[1]})
        self.data["blame"] = blame_list

    def _parse_timers(self):
        timers_text = self.raw_files.get("timers", "")
        timers = []
        lines = timers_text.strip().splitlines()
        for line in lines:
            line_s = line.strip()
            if not line_s or "ACTIVATES" in line_s or "timers listed" in line_s:
                continue
            if ".timer" in line_s:
                parts = line_s.split()
                timer_idx = -1
                for idx, tok in enumerate(parts):
                    if tok.endswith(".timer"):
                        timer_idx = idx
                        break
                if timer_idx != -1:
                    unit = parts[timer_idx]
                    activates = " ".join(parts[timer_idx + 1:]) if timer_idx + 1 < len(parts) else "-"
                    if "motd" in unit.lower() or "motd" in activates.lower():
                        continue
                    left_str = "-"
                    pre_parts = parts[:timer_idx]
                    if "left" in pre_parts:
                        l_idx = pre_parts.index("left")
                        left_str = " ".join(pre_parts[max(0, l_idx - 2):l_idx + 1])
                    next_str = " ".join(pre_parts[:4]) if len(pre_parts) >= 4 else "-"
                    timers.append({
                        "unit": unit,
                        "activates": activates,
                        "next": next_str,
                        "left": left_str,
                        "raw": line_s
                    })
        self.data["timers"] = timers

    def _parse_crontabs(self):
        user_jobs = []
        sys_jobs = []

        def parse_cron_lines(content, is_system, default_user="root", src=""):
            results = []
            last_comment = ""
            for line in content.splitlines():
                line_s = line.strip()
                if not line_s:
                    last_comment = ""
                    continue
                if line_s.startswith("#"):
                    c = line_s.lstrip("#").strip()
                    if c and not any(k in c.lower() for k in [
                        "do not edit", "cron version", "edit this file", "example of job",
                        "m h dom", "user-name command", "minute (", "hour ("
                    ]):
                        last_comment = c
                    continue
                if "=" in line_s and not line_s.startswith(("@", "*", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9")):
                    continue
                if "no crontab for" in line_s.lower():
                    continue

                if line_s.startswith("@"):
                    parts = line_s.split(None, 2 if is_system else 1)
                    if is_system and len(parts) >= 3:
                        results.append({
                            "type": "system",
                            "schedule": parts[0],
                            "user": parts[1],
                            "command": parts[2],
                            "comment": last_comment,
                            "source": src
                        })
                    elif not is_system and len(parts) >= 2:
                        results.append({
                            "type": "user",
                            "schedule": parts[0],
                            "user": default_user,
                            "command": parts[1],
                            "comment": last_comment,
                            "source": src
                        })
                else:
                    parts = line_s.split(None, 6 if is_system else 5)
                    if is_system and len(parts) >= 7:
                        results.append({
                            "type": "system",
                            "schedule": " ".join(parts[:5]),
                            "user": parts[5],
                            "command": parts[6],
                            "comment": last_comment,
                            "source": src
                        })
                    elif not is_system and len(parts) >= 6:
                        results.append({
                            "type": "user",
                            "schedule": " ".join(parts[:5]),
                            "user": default_user,
                            "command": parts[5],
                            "comment": last_comment,
                            "source": src
                        })
                last_comment = ""
            return results

        # 1. User crontabs
        user_crontabs = self.raw_files.get("user_crontabs", {})
        for uname, udata in user_crontabs.items():
            user_jobs.extend(parse_cron_lines(
                udata["content"],
                is_system=False,
                default_user=uname,
                src=udata["source"]
            ))

        root_cron_cmd = self.raw_files.get("root_crontab", "")
        if root_cron_cmd and "root" not in user_crontabs:
            root_src = self.data["source_paths"].get("root_crontab", "sos_commands/cron/root_crontab")
            user_jobs.extend(parse_cron_lines(
                root_cron_cmd,
                is_system=False,
                default_user="root",
                src=root_src
            ))

        # 2. System crontab (/etc/crontab)
        crontab_content = self.raw_files.get("crontab", "")
        if crontab_content:
            crontab_src = self.data["source_paths"].get("crontab", "etc/crontab")
            sys_jobs.extend(parse_cron_lines(
                crontab_content,
                is_system=True,
                default_user="root",
                src=crontab_src
            ))

        # 3. cron.d files
        cron_d_files = self.raw_files.get("cron_d", {})
        for fname, fdata in cron_d_files.items():
            sys_jobs.extend(parse_cron_lines(
                fdata["content"],
                is_system=True,
                default_user="root",
                src=fdata["source"]
            ))

        # Exclude motd
        user_jobs = [j for j in user_jobs if "motd" not in j["command"].lower() and "motd" not in j["comment"].lower()]
        sys_jobs = [j for j in sys_jobs if "motd" not in j["command"].lower() and "motd" not in j["comment"].lower()]

        periodic = self.raw_files.get("cron_periodic", {"hourly": [], "daily": [], "weekly": [], "monthly": []})

        self.data["crontabs"] = {
            "user_jobs": user_jobs,
            "system_jobs": sys_jobs,
            "all_jobs": user_jobs + sys_jobs,
            "periodic": periodic
        }

    def _parse_network(self):
        # IP addr
        ip_text = self.raw_files.get("ip_addr", "")
        ifaces = {}
        for line in ip_text.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4:
                name = parts[1].rstrip(":")
                if name not in ifaces:
                    ifaces[name] = {"name": name, "ipv4": [], "ipv6": [], "state": "UP"}
                if "inet" in parts:
                    idx = parts.index("inet")
                    if idx + 1 < len(parts):
                        ifaces[name]["ipv4"].append(parts[idx + 1])
                elif "inet6" in parts:
                    idx = parts.index("inet6")
                    if idx + 1 < len(parts):
                        ifaces[name]["ipv6"].append(parts[idx + 1])
        self.data["network"]["interfaces"] = list(ifaces.values())

        # Routes
        route_text = self.raw_files.get("ip_route", "")
        routes = []
        for line in route_text.splitlines():
            line_s = line.strip()
            if line_s and not line_s.startswith("multicast") and not line_s.startswith("broadcast"):
                routes.append(line_s)
        self.data["network"]["routes"] = routes[:10]

        # Netstat listening & active connections
        netstat_text = self.raw_files.get("netstat", "")
        listening = []
        connections = []
        for line in netstat_text.splitlines():
            parts = line.split()
            if not parts or parts[0] not in ("tcp", "tcp6", "udp", "udp6"):
                continue
            if len(parts) < 5:
                continue
            proto = parts[0]
            local = parts[3]
            foreign = parts[4]
            port = local.split(":")[-1] if ":" in local else local

            if "LISTEN" in line:
                prog = "-"
                for tok in parts[6:]:
                    if "/" in tok and not tok.startswith("(") and tok != "-":
                        prog = tok
                        break
                listening.append({
                    "proto": proto,
                    "local": local,
                    "port": port,
                    "program": prog
                })
            elif not foreign.endswith(":*") and foreign not in ("0.0.0.0:*", ":::*", "*:*"):
                state = "-"
                for st in ("ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING"):
                    if st in parts:
                        state = st
                        break
                if state == "-" and proto.startswith("udp"):
                    state = "ESTABLISHED" if "ESTABLISHED" in parts else "CONNECTED"

                prog = "-"
                for i, tok in enumerate(parts[5:], start=5):
                    if "/" in tok and not tok.startswith("(") and tok != "-":
                        prog_tokens = [tok]
                        for nxt in parts[i+1:]:
                            if nxt in ("off", "keepalive", "on") or nxt.startswith("("):
                                break
                            prog_tokens.append(nxt)
                        prog = " ".join(prog_tokens)
                        break

                foreign_host = foreign.rsplit(":", 1)[0] if ":" in foreign else foreign
                is_loopback = foreign_host.strip("[]") in ("127.0.0.1", "::1", "localhost")
                is_remote = not is_loopback

                connections.append({
                    "proto": proto,
                    "local": local,
                    "foreign": foreign,
                    "state": state,
                    "program": prog,
                    "is_remote": is_remote
                })

        connections.sort(key=lambda x: (not x["is_remote"], x["proto"], x["foreign"]))
        self.data["network"]["listening_ports"] = listening
        self.data["network"]["connections"] = connections

    def _parse_sysctl_and_dns(self):
        sysctl_text = self.raw_files.get("sysctl", "")
        sysctl_params = {}
        for line in sysctl_text.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if k in [
                    "net.core.somaxconn",
                    "vm.swappiness",
                    "fs.file-max",
                    "net.ipv4.ip_forward",
                    "net.ipv4.tcp_max_syn_backlog",
                    "vm.max_map_count",
                    "fs.inotify.max_user_watches"
                ]:
                    sysctl_params[k] = v
        self.data["sysctl"] = sysctl_params

        resolve_text = self.raw_files.get("resolvectl", "")
        dns_info = {"dns_servers": [], "domains": [], "protocols": []}
        for line in resolve_text.splitlines():
            line_s = line.strip()
            if "DNS Servers:" in line_s:
                dns_info["dns_servers"] = line_s.split("DNS Servers:", 1)[1].strip().split()
            elif "DNS Domain:" in line_s:
                dns_info["domains"] = line_s.split("DNS Domain:", 1)[1].strip().split()
            elif "Protocols:" in line_s and not dns_info["protocols"]:
                dns_info["protocols"] = line_s.split("Protocols:", 1)[1].strip().split()
        if not dns_info["dns_servers"]:
            for line in resolve_text.splitlines():
                if "Current DNS Server:" in line:
                    dns_info["dns_servers"] = [line.split("Current DNS Server:", 1)[1].strip()]
                    break
        self.data["dns"] = dns_info

    def _parse_processes(self):
        ps_text = self.raw_files.get("ps", "")
        procs = []
        lines = ps_text.strip().splitlines()
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    user, pid, cpu, mem, vsz, rss, tty, stat, start, time, cmd = parts
                    if cmd == "-" or pid == "-":
                        continue
                    try:
                        cpu_f = float(cpu)
                        mem_f = float(mem)
                        rss_mb = round(float(rss) / 1024, 1)
                    except ValueError:
                        continue
                    procs.append({
                        "user": user,
                        "pid": pid,
                        "cpu": cpu_f,
                        "mem": mem_f,
                        "rss_mb": rss_mb,
                        "stat": stat,
                        "time": time,
                        "cmd": cmd
                    })

        self.data["processes"]["all"] = procs[:50]
        self.data["processes"]["total_count"] = len(procs)
        self.data["processes"]["top_cpu"] = sorted(procs, key=lambda x: x["cpu"], reverse=True)[:10]
        self.data["processes"]["top_mem"] = sorted(procs, key=lambda x: x["mem"], reverse=True)[:10]

    def _parse_logs(self):
        dmesg_text = self.raw_files.get("dmesg_-T") or self.raw_files.get("dmesg", "")
        dmesg_lines = []
        issue_keywords = ["warning", "error", "failed", "fail", "oom", "panic", "segfault", "corrupt", "tainted", "vulnerable"]
        
        oom_count = 0
        segfault_count = 0
        io_error_count = 0

        for line in dmesg_text.splitlines():
            line_lower = line.lower()
            if "out of memory" in line_lower or "invoked oom-killer" in line_lower or "oom-killer" in line_lower:
                oom_count += 1
            if "segfault at" in line_lower:
                segfault_count += 1
            if any(k in line_lower for k in ["buffer i/o error", "blk_update_request: i/o error", "ext4-fs error"]):
                io_error_count += 1

            if any(k in line_lower for k in issue_keywords):
                if "0 errors" in line_lower or "error_injection" in line_lower or "motd" in line_lower:
                    continue
                dmesg_lines.append(line.strip())
        self.data["dmesg_issues"] = dmesg_lines[:40]

        journal_text = self.raw_files.get("journalctl_--no-pager_--boot", "")
        journal_lines = []
        for line in journal_text.splitlines():
            line_lower = line.lower()
            if "motd" in line_lower:
                continue
            if "out of memory" in line_lower or "invoked oom-killer" in line_lower:
                oom_count += 1
            if "segfault at" in line_lower:
                segfault_count += 1
            if any(k in line_lower for k in ["buffer i/o error", "blk_update_request: i/o error", "ext4-fs error"]):
                io_error_count += 1

            if any(k in line_lower for k in ["failed", "error", "crit", "alert", "fatal"]):
                if "0 failed" in line_lower or "no error" in line_lower or "uncompressed size" in line_lower:
                    continue
                journal_lines.append(line.strip())
        self.data["journal_issues"] = journal_lines[:40]

        self.data["log_audit"] = {
            "oom_count": oom_count,
            "segfault_count": segfault_count,
            "io_error_count": io_error_count
        }

    def _parse_security_and_apps(self):
        # Last logins
        last_text = self.raw_files.get("last", "")
        logins = []
        for line in last_text.splitlines()[:12]:
            parts = line.strip().split()
            if len(parts) >= 4 and not line.startswith("wtmp begins"):
                user = parts[0]
                tty = parts[1]
                ip = parts[2] if "." in parts[2] or ":" in parts[2] else "-"
                rest = " ".join(parts[3:])
                logins.append({"user": user, "tty": tty, "ip": ip, "time": rest})
        self.data["logins"] = logins

        # Nginx
        nginx_v = self.raw_files.get("nginx_-V", "")
        if nginx_v:
            m = re.search(r"nginx version:\s*([^\n\r]+)", nginx_v)
            v_str = m.group(1) if m else "Installed"
            self.data["nginx"] = {
                "detected": True,
                "version": v_str,
                "has_ssl": "--with-http_ssl_module" in nginx_v,
                "has_v2": "--with-http_v2_module" in nginx_v,
                "raw": nginx_v
            }
        else:
            self.data["nginx"] = {"detected": False}

    def _evaluate_health(self):
        findings = []
        score = 100

        # 1. Failed Services
        if self.data["failed_units"]:
            cnt = len(self.data["failed_units"])
            score -= (cnt * 10)
            u_names = ", ".join(u["unit"] for u in self.data["failed_units"])
            findings.append({
                "severity": "danger",
                "title_en": f"Failed Systemd Services ({cnt} detected)",
                "title_ko": f"실패한 시스템 서비스 ({cnt}개 감지됨)",
                "desc_en": f"The following service units are in failed state: {u_names}",
                "desc_ko": f"다음 서비스 유닛이 실패(failed) 상태입니다: {u_names}",
                "rec_en": "Inspect unit logs using `systemctl status <unit>` and restart or resolve configuration/permission issues.",
                "rec_ko": "`systemctl status <unit>` 명령어로 오류 로그를 확인하고 권한 및 실행 파일 설정을 조치하세요."
            })
        else:
            findings.append({
                "severity": "success",
                "title_en": "System Services Healthy",
                "title_ko": "시스템 서비스 정상 동작",
                "desc_en": "All systemd units are loaded and operating normally without failures.",
                "desc_ko": "모든 systemd 서비스 유닛이 정상적으로 로드되어 실행 중입니다.",
                "rec_en": "No action required.",
                "rec_ko": "별도 조치가 필요하지 않습니다."
            })

        # 2. Disk usage check
        high_disks = [d for d in self.data["disks"] if d["is_real_device"] and d["pct_num"] >= 85]
        warn_disks = [d for d in self.data["disks"] if d["is_real_device"] and 70 <= d["pct_num"] < 85]
        if high_disks:
            score -= 15
            disks_str = ", ".join(f"{d['mount']} ({d['pct']})" for d in high_disks)
            findings.append({
                "severity": "danger",
                "title_en": f"Critical Disk Usage on {disks_str}",
                "title_ko": f"디스크 공간 위험 ({disks_str})",
                "desc_en": f"Partition space is above 85%. Risk of service degradation or write failures.",
                "desc_ko": f"파티션 사용률이 85%를 초과했습니다. 쓰기 오류 및 서비스 장애 위험이 있습니다.",
                "rec_en": "Clean up temporary files, old journal logs (`journalctl --vacuum-time=3d`), or expand EBS volume.",
                "rec_ko": "임시 파일 및 저널 로그 정리(`journalctl --vacuum-time=3d`) 또는 EBS 볼륨 증설을 검토하세요."
            })
        elif warn_disks:
            disks_str = ", ".join(f"{d['mount']} ({d['pct']})" for d in warn_disks)
            findings.append({
                "severity": "warning",
                "title_en": f"Elevated Disk Space Usage on {disks_str}",
                "title_ko": f"디스크 사용량 주의 ({disks_str})",
                "desc_en": "Partition space is over 70%.",
                "desc_ko": "파티션 공간 사용률이 70%를 초과했습니다.",
                "rec_en": "Monitor disk growth trend and plan disk maintenance.",
                "rec_ko": "디스크 사용량 증가 추이를 모니터링하고 사전 용량 관리를 진행하세요."
            })
        else:
            findings.append({
                "severity": "success",
                "title_en": "Storage Capacity Healthy",
                "title_ko": "스토리지 공간 정상",
                "desc_en": "Root and mounted physical partitions have ample free space.",
                "desc_ko": "루트 및 마운트된 주요 파티션의 여유 공간이 충분합니다.",
                "rec_en": "Normal operational state.",
                "rec_ko": "정상 운영 상태입니다."
            })

        # 3. Memory & Swap
        mem = self.data["memory"]
        if mem["usage_pct"] > 90:
            score -= 15
            findings.append({
                "severity": "danger",
                "title_en": f"High Memory Consumption ({mem['usage_pct']}%)",
                "title_ko": f"높은 메모리 점유율 ({mem['usage_pct']}%)",
                "desc_en": f"Available memory is critically low: {mem['available_mb']} MB left.",
                "desc_ko": f"사용 가능한 여유 메모리가 매우 부족합니다: {mem['available_mb']} MB 남음.",
                "rec_en": "Investigate top memory processes or consider resizing instance.",
                "rec_ko": "메모리 점유 상위 프로세스를 확인하거나 인스턴스 스펙 상향을 검토하세요."
            })
        elif mem["usage_pct"] > 75:
            score -= 5
            findings.append({
                "severity": "warning",
                "title_en": f"Moderate Memory Pressure ({mem['usage_pct']}%)",
                "title_ko": f"메모리 사용률 주의 ({mem['usage_pct']}%)",
                "desc_en": f"Memory usage is elevated: {mem['used_mb']} MB used out of {mem['total_mb']} MB.",
                "desc_ko": f"메모리 점유가 다소 높습니다: 전체 {mem['total_mb']} MB 중 {mem['used_mb']} MB 사용 중.",
                "rec_en": "Keep track of memory consumers (e.g. Datadog agent, web server).",
                "rec_ko": "상위 메모리 프로세스(모니터링 에이전트, 웹 서버 등) 추이를 점검하세요."
            })
        else:
            findings.append({
                "severity": "success",
                "title_en": f"Memory Usage Normal ({mem['usage_pct']}%)",
                "title_ko": f"메모리 사용률 정상 ({mem['usage_pct']}%)",
                "desc_en": f"{mem['available_mb']} MB available out of {mem['total_mb']} MB total.",
                "desc_ko": f"전체 {mem['total_mb']} MB 중 {mem['available_mb']} MB를 즉시 활용할 수 있습니다.",
                "rec_en": "Memory headroom is sufficient.",
                "rec_ko": "충분한 메모리 여유가 확보되어 있습니다."
            })

        # 4. CPU Load
        cores = self.data["cpu"].get("cores", 1)
        load1 = self.data["system"].get("load_1m", 0)
        if load1 > cores * 2.0:
            score -= 10
            findings.append({
                "severity": "danger",
                "title_en": f"High CPU Load Average ({load1:.2f} on {cores} cores)",
                "title_ko": f"높은 CPU 부하 ({cores}개 코어 기준 {load1:.2f})",
                "desc_en": "System load significantly exceeds available CPU core capacity.",
                "desc_ko": "시스템 평균 부하가 CPU 가용 코어 용량을 크게 초과했습니다.",
                "rec_en": "Check top CPU consuming processes and identify execution spikes.",
                "rec_ko": "CPU 점유 상위 프로세스를 확인하여 비정상 프로세스 급증 원인을 분석하세요."
            })
        elif load1 > cores:
            findings.append({
                "severity": "warning",
                "title_en": f"Elevated CPU Load Average ({load1:.2f} on {cores} cores)",
                "title_ko": f"CPU 부하 주의 ({cores}개 코어 기준 {load1:.2f})",
                "desc_en": "System load is slightly higher than the core count.",
                "desc_ko": "시스템 부하가 보유 코어 수보다 다소 높습니다.",
                "rec_en": "Observe process activities during peak hours.",
                "rec_ko": "피크 시간대 작업량 및 백그라운드 배치 작업을 점검하세요."
            })
        else:
            findings.append({
                "severity": "success",
                "title_en": "CPU Load Normal",
                "title_ko": "CPU 부하 상태 정상",
                "desc_en": f"Load average ({load1:.2f}) is stable within {cores} vCPUs.",
                "desc_ko": f"현재 부하율({load1:.2f})이 {cores}개 vCPU 범위 내에서 안정적입니다.",
                "rec_en": "Normal operational state.",
                "rec_ko": "안정적인 부하 상태를 유지하고 있습니다."
            })

        # 5. Kernel / Hardware Security
        retbleed = any("retbleed" in l.lower() for l in self.data["dmesg_issues"])
        if retbleed:
            findings.append({
                "severity": "warning",
                "title_en": "Kernel Mitigation Warning (RETBleed / Spectre v2)",
                "title_ko": "커널 보안 완화 경고 (RETBleed / Spectre v2)",
                "desc_en": "CPU vulnerable to RETBleed attacks; standard cloud hypervisor mitigation advisory.",
                "desc_ko": "클라우드 하이퍼바이저 상에서 RETBleed 완화 권고 경고가 dmesg에 기록되었습니다.",
                "rec_en": "Ensure kernel and microcode updates are applied according to AWS security bulletins.",
                "rec_ko": "AWS 보안 권고에 따라 최신 커널 보안 패치가 적용되어 있는지 확인하세요."
            })

        # 6. SSH Remote Access Security
        ssh_cfg = self.data.get("ssh_config", {})
        pwd_auth = ssh_cfg.get("passwordauthentication", "").lower()
        ssh_port = ssh_cfg.get("port", "22")
        if pwd_auth == "yes":
            score -= 10
            findings.append({
                "severity": "warning",
                "title_en": f"SSH Password Authentication Enabled (Port {ssh_port})",
                "title_ko": f"SSH 비밀번호 인증 활성화 (포트 {ssh_port})",
                "desc_en": f"sshd allows password-based authentication (`PasswordAuthentication yes`). EC2 Bastion hosts should enforce key-based access to mitigate brute-force credential stuffing.",
                "desc_ko": f"SSH 데몬 설정에서 비밀번호 인증이 허용되어 있습니다 (`PasswordAuthentication yes`). EC2 배스천 호스트의 무차별 대입 공격을 차단하기 위해 공개키 인증 전용으로 제한해야 합니다.",
                "rec_en": "Edit `/etc/ssh/sshd_config` and set `PasswordAuthentication no`, then reload sshd.",
                "rec_ko": "`/etc/ssh/sshd_config` 파일에서 `PasswordAuthentication no`로 변경한 후 sshd 서비스를 재시작하세요."
            })
        elif pwd_auth == "no":
            findings.append({
                "severity": "success",
                "title_en": "SSH Hardened (Key-based Authentication Only)",
                "title_ko": "SSH 보안 강화 (공개키 전용 인증 적용됨)",
                "desc_en": f"Password authentication is disabled on port {ssh_port}. Only authenticated keys are permitted.",
                "desc_ko": f"포트 {ssh_port}에서 비밀번호 인증이 비활성화되어 안전하게 키 기반 인증만 허용됩니다.",
                "rec_en": "Maintain private key access controls and rotate authorized keys periodically.",
                "rec_ko": "접속용 개인키 보안을 유지하고 정기적으로 승인 키를 로테이션하세요."
            })

        # 7. Inode Capacity Health
        high_inodes = [d for d in self.data["disks"] if d["is_real_device"] and d.get("iuse_num", 0) >= 85]
        if high_inodes:
            score -= 10
            inodes_str = ", ".join(f"{d['mount']} ({d.get('iuse_pct')})" for d in high_inodes)
            findings.append({
                "severity": "danger",
                "title_en": f"Critical Inode Exhaustion on {inodes_str}",
                "title_ko": f"Inode 공간 고갈 위험 ({inodes_str})",
                "desc_en": "Inode usage exceeds 85%. New files cannot be created even if disk storage space is free.",
                "desc_ko": "Inode 사용률이 85%를 초과했습니다. 디스크 용량이 남아있어도 새 파일을 생성할 수 없게 됩니다.",
                "rec_en": "Delete accumulated small files, old session files, or email queues.",
                "rec_ko": "임시 파일, 다량의 세션 파일, 캐시 파일 등 불필요한 소용량 파일을 정리하세요."
            })
        else:
            findings.append({
                "severity": "success",
                "title_en": "Filesystem Inodes Healthy",
                "title_ko": "파일시스템 Inode 여유 공간 정상",
                "desc_en": "Sufficient filesystem index node (inode) capacity is available across all partitions.",
                "desc_ko": "모든 물리 파티션의 Inode 가용 수량이 충분하여 파일 생성이 원활합니다.",
                "rec_en": "No action required.",
                "rec_ko": "정상 상태입니다."
            })

        # 8. Crash & OOM Audit
        audit = self.data.get("log_audit", {})
        if audit.get("oom_count", 0) > 0:
            score -= 15
            findings.append({
                "severity": "danger",
                "title_en": f"Kernel OOM Killer Triggered ({audit['oom_count']} events)",
                "title_ko": f"커널 OOM 킬러 프로세스 강제 종료 ({audit['oom_count']}건 감지)",
                "desc_en": "The kernel ran out of memory and terminated processes to prevent an operating system crash.",
                "desc_ko": "메모리 고갈로 인해 커널 OOM 킬러가 프로세스를 강제 종료했습니다.",
                "rec_en": "Identify memory leaks in services or upgrade instance RAM.",
                "rec_ko": "메모리 누수가 발생하는 프로세스를 점검하거나 인스턴스 메모리를 증설하세요."
            })
        if audit.get("io_error_count", 0) > 0:
            score -= 15
            findings.append({
                "severity": "danger",
                "title_en": f"Disk / Block I/O Errors Detected ({audit['io_error_count']} events)",
                "title_ko": f"디스크/블록 I/O 에러 감지 ({audit['io_error_count']}건 감지)",
                "desc_en": "Hardware or filesystem I/O errors logged by the kernel.",
                "desc_ko": "커널 로그에 파일시스템 또는 디스크 I/O 오류가 기록되었습니다.",
                "rec_en": "Inspect EBS volume performance and check filesystem integrity with e2fsck.",
                "rec_ko": "EBS 볼륨 성능 상태 및 파일시스템 무결성을 점검하세요."
            })

        self.data["health_score"] = max(0, min(100, score))
        self.data["findings"] = findings


class HTMLReportGenerator:
    def __init__(self, data):
        self.d = data

    def generate(self) -> str:
        score = self.d["health_score"]
        status_color = "#10b981" if score >= 85 else ("#f59e0b" if score >= 65 else "#ef4444")
        status_label_en = "HEALTHY" if score >= 85 else ("ATTENTION" if score >= 65 else "CRITICAL")
        status_label_ko = "정상" if score >= 85 else ("점검 필요" if score >= 65 else "위험")
        status_key = "status_healthy" if score >= 85 else ("status_attention" if score >= 65 else "status_critical")

        json_dump = json.dumps(self.d, indent=2, ensure_ascii=False)

        src = self.d.get("source_paths", {})
        def make_ref_badge(path_str):
            return f'<div class="ref-path"><span>📁</span> <span data-i18n="ref_source">참조 파일:</span> <code>{path_str}</code></div>'

        ref_diag = f"{src.get('manifest.json', 'sos_reports/manifest.json')}, {src.get('uptime', 'sos_commands/host/uptime')}, {src.get('dmesg', 'sos_commands/kernel/dmesg')}"
        ref_host = f"{src.get('hostname', 'sos_commands/host/hostname')}, {src.get('uname', 'sos_commands/kernel/uname_-a')}, {src.get('lsb-release', 'etc/lsb-release')}"
        ref_logins = src.get('last', 'sos_commands/login/last_-F')
        ref_users = f"{src.get('lslogins', 'sos_commands/login/lslogins')}, {src.get('getent_passwd', 'sos_commands/getent/getent_passwd')}, etc/sudoers, etc/sudoers.d/*"
        ref_storage = src.get('df', 'sos_commands/filesys/df_-al_-x_autofs')
        ref_df_inodes = src.get('df_inodes', 'sos_commands/filesys/df_-aliT_-x_autofs')
        ref_lsblk = src.get('lsblk', 'sos_commands/block/lsblk')
        ref_lscpu = src.get('lscpu', 'sos_commands/processor/lscpu')
        ref_cpuinfo = src.get('cpuinfo', 'proc/cpuinfo')
        ref_mem = src.get('free', 'sos_commands/memory/free')
        ref_meminfo = src.get('meminfo', 'proc/meminfo')
        ref_failed_units = src.get('systemctl_list-units_--failed', 'sos_commands/systemd/systemctl_list-units_--failed')
        ref_blame = src.get('systemd-analyze_blame', 'sos_commands/systemd/systemd-analyze_blame')
        ref_net = f"{src.get('ip_addr', 'sos_commands/networking/ip_-o_addr')}, {src.get('ip_route', 'sos_commands/networking/ip_route')}"
        ref_ports = src.get('netstat', 'sos_commands/networking/netstat_-W_-neopa')
        ref_connections = src.get('netstat', 'sos_commands/networking/netstat_-W_-neopa')
        ref_ssh = src.get('sshd_-T', 'sos_commands/ssh/sshd_-T')
        ref_timers = src.get('timers', 'sos_commands/systemd/systemctl_list-timers_--all')
        ref_crontab = src.get('crontabs', 'etc/crontab, var/spool/cron/crontabs/*, etc/cron.d/*')
        ref_sysctl = src.get('sysctl', 'sos_commands/kernel/sysctl_-a')
        ref_dns = src.get('resolvectl', 'sos_commands/systemd/resolvectl_status')
        ref_procs = src.get('ps', 'sos_commands/process/ps_auxwwwm')
        ref_dmesg = src.get('dmesg', 'sos_commands/kernel/dmesg')
        ref_journal = src.get('journalctl_--no-pager_--boot', 'sos_commands/logs/journalctl_--no-pager_--boot')
        ref_json = "sosreport.py (In-Memory Aggregated)"

        # Build User Rows
        user_rows = ""
        for u in self.d.get("users", []):
            if u["uid"] == 0:
                type_badge = '<div><span class="badge badge-danger">👑 <span data-i18n="type_root">최고 관리자 (Root)</span></span></div>'
            elif u.get("has_sudo"):
                base_type = '<span class="badge badge-primary" data-i18n="type_regular">일반 사용자</span>' if u['is_regular'] else '<span class="badge badge-secondary" data-i18n="type_system">시스템 계정</span>'
                rule_snippet = f'<div style="margin-top: 4px; font-size: 0.72rem; color: var(--text-muted);"><span style="color: #f59e0b; font-weight: 600;">Sudo:</span> <code class="code-sm">{u.get("sudo_rule", "ALL")}</code></div>' if u.get("sudo_rule") else ''
                type_badge = f'''
                <div>
                    {base_type} <span class="badge badge-warning" style="background: rgba(245, 158, 11, 0.18); color: #f59e0b; font-weight: 700; margin-left: 3px;">🛡️ <span data-i18n="has_sudo_priv">관리자 권한 포함</span></span>
                    {rule_snippet}
                </div>
                '''
            else:
                type_badge = '<span class="badge badge-primary" data-i18n="type_regular">일반 사용자</span>' if u['is_regular'] else '<span class="badge badge-secondary" data-i18n="type_system">시스템 계정</span>'

            if u["is_interactive"]:
                shell_badge = f'<span class="badge badge-success" style="font-family: monospace;">{u["shell"]}</span>'
            else:
                shell_badge = f'<code class="code-sm">{u["shell"]}</code>'

            proc_val = f'<strong style="color: #38bdf8;">{u["proc_count"]}</strong>' if u["proc_count"] != "0" else '<span style="color: var(--text-muted);">0</span>'
            last_login_val = u['last_login'] if u['last_login'] != '-' else '<span style="color: var(--text-muted);">-</span>'

            user_rows += f"""
            <tr>
                <td><strong>{u['username']}</strong></td>
                <td><code>{u['uid']}:{u['gid']}</code></td>
                <td>{type_badge}</td>
                <td>{shell_badge}</td>
                <td><code class="code-sm">{u['home']}</code></td>
                <td style="text-align: center;">{proc_val}</td>
                <td><small>{last_login_val}</small></td>
            </tr>
            """

        # Build Block Devices HTML (Local & Additional Disks)
        blk = self.d.get("block_devices", {"local_disks": [], "additional_disks": []})
        local_disks = blk.get("local_disks", [])
        additional_disks = blk.get("additional_disks", [])

        local_disk_html = ""
        if local_disks:
            for ld in local_disks:
                parts_html = ""
                for p in ld.get("partitions", []):
                    m_label = f"<code>{p['mount']}</code>" if p['mount'] else '<span style="color: var(--text-muted);">-</span>'
                    parts_html += f"""
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; background: var(--bg-card); border-radius: 6px; margin-top: 5px; font-size: 0.82rem; border: 1px solid var(--border-sub);">
                        <span><code class="code-sm">{p['name']}</code> <span style="color: var(--text-muted); margin-left: 6px;">({p['size']})</span></span>
                        <span>{m_label}</span>
                    </div>
                    """
                local_disk_html += f"""
                <div class="card" style="margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <div>
                            <strong style="color: var(--primary); font-size: 1rem;">{ld['device']}</strong>
                            <span class="badge badge-primary" style="margin-left: 6px;" data-i18n="badge_local_disk">로컬 / OS 디스크</span>
                        </div>
                        <span style="font-weight: 700; font-size: 1rem; color: var(--text-main);">{ld['size']}</span>
                    </div>
                    <div style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 6px;" data-i18n="partitions_layout">
                        파티션 구성 ({len(ld.get('partitions', []))}개):
                    </div>
                    {parts_html}
                </div>
                """
        else:
            local_disk_html = '<div style="color: var(--text-muted); font-size: 0.85rem;" data-i18n="no_local_disk">로컬 디스크 정보 없음</div>'

        additional_disk_html = ""
        if additional_disks:
            for ad in additional_disks:
                parts_html = ""
                for p in ad.get("partitions", []):
                    m_label = f"<code>{p['mount']}</code>" if p['mount'] else '<span style="color: var(--text-muted);">-</span>'
                    parts_html += f"""
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; background: var(--bg-card); border-radius: 6px; margin-top: 5px; font-size: 0.82rem; border: 1px solid var(--border-sub);">
                        <span><code class="code-sm">{p['name']}</code> <span style="color: var(--text-muted); margin-left: 6px;">({p['size']})</span></span>
                        <span>{m_label}</span>
                    </div>
                    """
                m_info = f"<code>{ad['mount']}</code>" if ad['mount'] else '<span style="color: var(--text-muted);" data-i18n="unmounted_data">미마운트 / 데이터 (Unmounted)</span>'
                additional_disk_html += f"""
                <div class="card" style="margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <div>
                            <strong style="color: #a855f7; font-size: 1rem;">{ad['device']}</strong>
                            <span class="badge badge-secondary" style="margin-left: 6px;" data-i18n="badge_extra_vol">추가 볼륨</span>
                        </div>
                        <span style="font-weight: 700; font-size: 1rem; color: var(--text-main);">{ad['size']}</span>
                    </div>
                    <div style="font-size: 0.82rem; margin-top: 6px;">
                        <span style="color: var(--text-muted);" data-i18n="disk_mount_role">용도 / 마운트:</span> {m_info}
                    </div>
                    {parts_html}
                </div>
                """
        else:
            additional_disk_html = f"""
            <div class="card" style="text-align: center; padding: 28px 16px; border: 1px dashed var(--border); color: var(--text-muted);">
                <div style="font-size: 1.4rem; margin-bottom: 6px;">📭</div>
                <div style="font-weight: 700; font-size: 0.95rem; color: var(--text-main);" data-i18n="no_additional_disks">없음 (None)</div>
                <div style="font-size: 0.8rem; margin-top: 4px;" data-i18n="no_additional_disks_sub">루트 OS 디스크 외에 별도로 연결된 추가 블록 볼륨이 없습니다.</div>
            </div>
            """

        # Build Disk rows
        disk_rows = ""
        for disk in self.d["disks"]:
            p = disk["pct_num"]
            p_color = "#10b981" if p < 70 else ("#f59e0b" if p < 85 else "#ef4444")
            badge = '<span class="badge badge-primary">Disk</span>' if disk["is_real_device"] else '<span class="badge badge-secondary">Virtual</span>'
            ip_val = disk.get("iuse_pct", "-")
            ip_num = disk.get("iuse_num", 0)
            ip_color = "#10b981" if ip_num < 70 else ("#f59e0b" if ip_num < 85 else "#ef4444")
            inode_badge = f'<span style="font-weight:600; color:{ip_color};">{ip_val}</span>' if ip_val != '-' else '<span style="color:var(--text-muted);">-</span>'
            inodes_total = disk.get("inodes", "-")

            disk_rows += f"""
            <tr>
                <td><strong>{disk['mount']}</strong></td>
                <td><code class="code-sm">{disk['filesystem']}</code> {badge}</td>
                <td>{disk['size']}</td>
                <td>{disk['used']}</td>
                <td>{disk['avail']}</td>
                <td style="min-width: 130px;">
                    <div class="progress-box">
                        <div class="progress-bar" style="width: {p}%; background: {p_color};"></div>
                    </div>
                    <span style="font-size: 0.8rem; font-weight: 600; color: {p_color};">{disk['pct']}</span>
                </td>
                <td><code>{inodes_total}</code></td>
                <td>{inode_badge}</td>
            </tr>
            """

        # Build Failed Unit rows
        failed_rows = ""
        if self.d["failed_units"]:
            for u in self.d["failed_units"]:
                log_box = f'<pre class="log-pre" style="margin-top: 8px;">{u["log"]}</pre>' if u["log"] else ''
                failed_rows += f"""
                <div class="card card-danger" style="margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 700; font-size: 1rem; color: #ef4444;">● {u['unit']}</span>
                        <span class="badge badge-danger">FAILED</span>
                    </div>
                    <div style="color: var(--text-muted); font-size: 0.85rem; margin-top: 4px;">{u['desc']}</div>
                    {log_box}
                </div>
                """
        else:
            failed_rows = '<div class="alert alert-success i18n-elem" data-ko="실패한 systemd 서비스가 없습니다! 모든 유닛이 정상 실행 중입니다." data-en="No failed systemd services detected! System is running cleanly.">실패한 systemd 서비스가 없습니다! 모든 유닛이 정상 실행 중입니다.</div>'

        # Build Top CPU processes
        cpu_proc_rows = ""
        for p in self.d["processes"]["top_cpu"][:8]:
            cpu_proc_rows += f"""
            <tr>
                <td><code>{p['pid']}</code></td>
                <td>{p['user']}</td>
                <td><strong style="color: #38bdf8;">{p['cpu']}%</strong></td>
                <td>{p['mem']}% ({p['rss_mb']} MB)</td>
                <td><code class="code-sm" title="{p['cmd']}">{p['cmd'][:60]}</code></td>
            </tr>
            """

        # Build Top Mem processes
        mem_proc_rows = ""
        for p in self.d["processes"]["top_mem"][:8]:
            mem_proc_rows += f"""
            <tr>
                <td><code>{p['pid']}</code></td>
                <td>{p['user']}</td>
                <td>{p['cpu']}%</td>
                <td><strong style="color: #a855f7;">{p['mem']}%</strong> ({p['rss_mb']} MB)</td>
                <td><code class="code-sm" title="{p['cmd']}">{p['cmd'][:60]}</code></td>
            </tr>
            """

        # Build All Procs (Top 50)
        all_proc_rows = ""
        for p in self.d["processes"]["all"]:
            all_proc_rows += f"""
            <tr>
                <td><code>{p['pid']}</code></td>
                <td>{p['user']}</td>
                <td><strong>{p['cpu']}%</strong></td>
                <td>{p['mem']}% ({p['rss_mb']} MB)</td>
                <td><span class="badge badge-outline">{p['stat']}</span></td>
                <td><code class="code-sm" title="{p['cmd']}">{p['cmd'][:85]}</code></td>
            </tr>
            """

        # Build Listening Ports
        port_rows = ""
        for pt in self.d["network"]["listening_ports"]:
            port_rows += f"""
            <tr>
                <td><span class="badge badge-outline">{pt['proto'].upper()}</span></td>
                <td><strong>{pt['port']}</strong></td>
                <td><code>{pt['local']}</code></td>
                <td><span style="color: #38bdf8; font-weight: 600;">{pt['program']}</span></td>
            </tr>
            """

        # Build Active Network Connections
        all_conns = self.d["network"].get("connections", [])
        remote_conns = [c for c in all_conns if c.get("is_remote")]
        conn_rows = ""
        for c in all_conns:
            if c.get("is_remote"):
                type_badge = '<span class="badge badge-primary" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; font-weight: 600;" data-i18n="conn_type_remote">🌐 원격 서버</span>'
                foreign_styled = f'<strong style="color: #38bdf8; font-family: monospace;">{c["foreign"]}</strong>'
            else:
                type_badge = '<span class="badge badge-outline" style="color: var(--text-muted); font-size: 0.75rem;" data-i18n="conn_type_local">🔄 로컬 루프백</span>'
                foreign_styled = f'<code style="color: var(--text-muted);">{c["foreign"]}</code>'

            state_upper = c['state'].upper()
            if state_upper == "ESTABLISHED":
                state_badge = f'<span class="badge badge-success">{state_upper}</span>'
            elif state_upper in ("TIME_WAIT", "CLOSE_WAIT"):
                state_badge = f'<span class="badge badge-warning">{state_upper}</span>'
            elif state_upper in ("SYN_SENT", "SYN_RECV"):
                state_badge = f'<span class="badge badge-danger">{state_upper}</span>'
            else:
                state_badge = f'<span class="badge badge-secondary">{state_upper}</span>'

            conn_rows += f"""
            <tr>
                <td><span class="badge badge-outline">{c['proto'].upper()}</span></td>
                <td>{type_badge}</td>
                <td><code>{c['local']}</code></td>
                <td>{foreign_styled}</td>
                <td>{state_badge}</td>
                <td><span style="color: var(--text-main); font-weight: 500;">{c['program']}</span></td>
            </tr>
            """
        if not conn_rows:
            conn_rows = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);" data-i18n="no_conns">활성 네트워크 연결이 없습니다.</td></tr>'

        # Build Network Interfaces
        iface_cards = ""
        for iface in self.d["network"]["interfaces"]:
            v4_str = ", ".join(f"<code>{ip}</code>" for ip in iface["ipv4"]) or "None"
            v6_str = ", ".join(f"<code style='font-size: 0.75rem;'>{ip}</code>" for ip in iface["ipv6"]) or "None"
            iface_cards += f"""
            <div class="card" style="margin-bottom: 12px; background: var(--bg-card-sub);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-weight: 700; font-size: 1.05rem; color: #38bdf8;">{iface['name']}</span>
                    <span class="badge badge-success">UP</span>
                </div>
                <div style="font-size: 0.85rem; color: var(--text-main);"><strong>IPv4:</strong> {v4_str}</div>
                <div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 4px;"><strong>IPv6:</strong> {v6_str}</div>
            </div>
            """

        # Build Findings Cards (Bilingual)
        finding_cards = ""
        for f in self.d["findings"]:
            b_class = f"card-{f['severity']}"
            badge_class = f"badge-{f['severity']}"
            badge_text = f['severity'].upper()
            t_ko = f.get('title_ko', f.get('title', ''))
            t_en = f.get('title_en', f.get('title', ''))
            d_ko = f.get('desc_ko', f.get('desc', ''))
            d_en = f.get('desc_en', f.get('desc', ''))
            r_ko = f.get('rec_ko', f.get('recommendation', ''))
            r_en = f.get('rec_en', f.get('recommendation', ''))
            finding_cards += f"""
            <div class="card {b_class}" style="margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h4 class="i18n-elem" data-ko="{t_ko}" data-en="{t_en}" style="margin: 0; font-size: 0.95rem;">{t_ko}</h4>
                    <span class="badge {badge_class}">{badge_text}</span>
                </div>
                <p class="i18n-elem" data-ko="{d_ko}" data-en="{d_en}" style="margin: 6px 0; font-size: 0.85rem; color: var(--text-main);">{d_ko}</p>
                <div style="font-size: 0.8rem; border-top: 1px dashed var(--border); padding-top: 6px; margin-top: 6px; color: var(--text-muted);">
                    💡 <strong data-i18n="action_label">권장 조치:</strong> <span class="i18n-elem" data-ko="{r_ko}" data-en="{r_en}">{r_ko}</span>
                </div>
            </div>
            """

        # Boot Blame rows
        blame_rows = ""
        for b in self.d["blame"]:
            blame_rows += f"""
            <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--border-sub); font-size: 0.85rem;">
                <code style="color: var(--text-main);">{b['service']}</code>
                <span style="color: #f59e0b; font-weight: 600;">{b['time']}</span>
            </div>
            """

        # Log Issues
        dmesg_html = "\n".join(self.d["dmesg_issues"][:25]) or "No critical dmesg warnings found."
        journal_html = "\n".join(self.d["journal_issues"][:25]) or "No critical journal errors found."

        # Recent logins
        login_rows = ""
        for l in self.d["logins"]:
            login_rows += f"""
            <tr>
                <td><strong>{l['user']}</strong></td>
                <td>{l['tty']}</td>
                <td><code>{l['ip']}</code></td>
                <td style="color: var(--text-muted);">{l['time']}</td>
            </tr>
            """

        # SSH Security Audit
        ssh_cfg = self.d.get("ssh_config", {})
        pwd_auth = ssh_cfg.get("passwordauthentication", "unknown")
        pwd_badge = '<span class="badge badge-warning" data-i18n="badge_enabled_warn">⚠️ 활성화됨 (위험)</span>' if pwd_auth == "yes" else '<span class="badge badge-success" data-i18n="badge_disabled_safe">✅ 비활성화됨 (안전)</span>'
        root_login = ssh_cfg.get("permitrootlogin", "unknown")
        root_badge = '<span class="badge badge-primary">Key Only (without-password)</span>' if root_login in ("without-password", "prohibit-password") else f'<span class="badge badge-warning">{root_login}</span>'
        pub_auth = ssh_cfg.get("pubkeyauthentication", "unknown")
        pub_badge = '<span class="badge badge-success">Enabled (yes)</span>' if pub_auth == "yes" else f'<span class="badge badge-danger">{pub_auth}</span>'
        ssh_port = ssh_cfg.get("port", "22")

        # Systemd Timers
        timer_rows = ""
        timers_list = self.d.get("timers", [])
        if timers_list:
            for t in timers_list:
                timer_rows += f"""
                <tr>
                    <td><strong style="color: #38bdf8;">{t['unit']}</strong></td>
                    <td><code>{t['next']}</code></td>
                    <td><span class="badge badge-outline">{t['left']}</span></td>
                    <td><span style="color: var(--text-muted); font-size: 0.85rem;">{t['activates']}</span></td>
                </tr>
                """
        else:
            timer_rows = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);" data-i18n="no_timers">등록된 시스템 타이머가 없습니다.</td></tr>'

        # Crontab & Scheduled Jobs
        def format_cron_schedule(sched):
            sched_s = sched.strip()
            if sched_s == "@reboot":
                return "부팅 시 (At Reboot)"
            if sched_s == "@hourly":
                return "매시간 정각 (Hourly)"
            if sched_s in ("@daily", "@midnight"):
                return "매일 자정 (Daily 00:00)"
            if sched_s == "@weekly":
                return "매주 일요일 자정 (Weekly Sun 00:00)"
            if sched_s == "@monthly":
                return "매월 1일 자정 (Monthly 1st 00:00)"
            parts = sched_s.split()
            if len(parts) == 5:
                m, h, dom, mon, dow = parts
                if dom == "*" and mon == "*" and dow == "*":
                    if m.isdigit() and h.isdigit():
                        return f"매일 {int(h):02d}:{int(m):02d}"
                    if h == "*" and m.isdigit():
                        return f"매시 {int(m):02d}분"
                    if m.startswith("*/"):
                        return f"{m[2:]}분 주기"
                if dom == "*" and mon == "*" and dow.isdigit():
                    days_ko = ["일", "월", "화", "수", "목", "금", "토", "일"]
                    d_idx = int(dow)
                    day_name = days_ko[d_idx] if d_idx < len(days_ko) else dow
                    if m.isdigit() and h.isdigit():
                        return f"매주 ({day_name}) {int(h):02d}:{int(m):02d}"
                if dom.isdigit() and mon == "*" and dow == "*":
                    if m.isdigit() and h.isdigit():
                        return f"매월 {dom}일 {int(h):02d}:{int(m):02d}"
            return sched_s

        cron_data = self.d.get("crontabs", {})
        all_cron_jobs = cron_data.get("all_jobs", [])
        total_cron_count = len(all_cron_jobs)
        cron_rows = ""
        if all_cron_jobs:
            for j in all_cron_jobs:
                user_type_badge = (
                    f'<span class="badge badge-warning" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; font-weight: 600;">👤 {j["user"]}</span>'
                    if j.get("type") == "user"
                    else f'<span class="badge badge-secondary" style="font-weight: 600;">⚙️ {j["user"]}</span>'
                )
                sched_badge = f'<span class="badge badge-outline" style="margin-left: 6px; font-weight: 500;">{format_cron_schedule(j["schedule"])}</span>'
                comment_html = (
                    f'<span style="color: #38bdf8; font-weight: 500;">{j["comment"]}</span>'
                    if j.get("comment")
                    else '<span style="color: var(--text-muted);">-</span>'
                )
                cron_rows += f"""
                <tr>
                    <td>{user_type_badge}</td>
                    <td><code>{j['schedule']}</code> {sched_badge}</td>
                    <td><code style="word-break: break-all;">{j['command']}</code></td>
                    <td>{comment_html}</td>
                    <td><code class="code-sm">{j['source']}</code></td>
                </tr>
                """
        else:
            cron_rows = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);" data-i18n="no_crons">등록된 Crontab 예약 작업이 없습니다.</td></tr>'

        periodic = cron_data.get("periodic", {})
        periodic_hourly = periodic.get("hourly", [])
        periodic_daily = periodic.get("daily", [])
        periodic_weekly = periodic.get("weekly", [])
        periodic_monthly = periodic.get("monthly", [])

        def make_script_badges(scripts):
            if not scripts:
                return '<span style="color: var(--text-muted); font-size: 0.8rem;" data-i18n="none_text">없음 (None)</span>'
            return " ".join(f'<span class="badge badge-outline" style="margin: 2px; font-size: 0.75rem;">{s}</span>' for s in scripts)

        badges_hourly = make_script_badges(periodic_hourly)
        badges_daily = make_script_badges(periodic_daily)
        badges_weekly = make_script_badges(periodic_weekly)
        badges_monthly = make_script_badges(periodic_monthly)

        # CPU Info & Meminfo Analysis Variables
        cpu_data = self.d.get("cpu", {})
        cpuinfo = cpu_data.get("cpuinfo", {})
        cpu_virt_badges = " ".join(f'<span class="badge badge-primary">{v}</span>' for v in cpuinfo.get("virtualization", [])) or '<span style="color: var(--text-muted); font-size: 0.8rem;">-</span>'
        cpu_simd_badges = " ".join(f'<span class="badge badge-outline" style="font-size: 0.72rem; margin: 2px;">{s}</span>' for s in cpuinfo.get("simd", [])) or '<span style="color: var(--text-muted); font-size: 0.8rem;">-</span>'
        cpu_sec_badges = " ".join(f'<span class="badge badge-success" style="font-size: 0.72rem; margin: 2px;">{sec}</span>' for sec in cpuinfo.get("crypto_security", [])) or '<span style="color: var(--text-muted); font-size: 0.8rem;">-</span>'

        cpu_bugs = cpuinfo.get("bugs", [])
        if cpu_bugs:
            cpu_bug_badges = " ".join(f'<span class="badge badge-warning" style="font-size: 0.72rem; margin: 2px;">⚠️ {b}</span>' for b in cpu_bugs[:12])
            if len(cpu_bugs) > 12:
                cpu_bug_badges += f' <span class="badge badge-secondary" style="font-size: 0.72rem;">+{len(cpu_bugs) - 12} more</span>'
        else:
            cpu_bug_badges = '<span class="badge badge-success">감지된 취약점 없음 (None)</span>'

        meminfo = self.d.get("memory", {}).get("meminfo", {})
        m_tot_mb = meminfo.get("total_kb", 0) / 1024
        m_avail_mb = meminfo.get("available_kb", 0) / 1024
        m_avail_pct = round((m_avail_mb / max(1, m_tot_mb)) * 100, 1)
        m_slab_mb = meminfo.get("slab_kb", 0) / 1024
        m_srec_mb = meminfo.get("s_reclaimable_kb", 0) / 1024
        m_sunrec_mb = meminfo.get("s_unreclaim_kb", 0) / 1024
        m_commit_mb = meminfo.get("committed_as_kb", 0) / 1024
        m_limit_mb = meminfo.get("commit_limit_kb", 0) / 1024
        m_commit_pct = meminfo.get("commit_ratio_pct", 0)
        m_dirty_mb = meminfo.get("dirty_kb", 0) / 1024
        m_wb_mb = meminfo.get("writeback_kb", 0) / 1024
        m_act_anon = meminfo.get("active_anon_kb", 0) / 1024
        m_inact_anon = meminfo.get("inactive_anon_kb", 0) / 1024
        m_act_file = meminfo.get("active_file_kb", 0) / 1024
        m_inact_file = meminfo.get("inactive_file_kb", 0) / 1024
        m_pgtables = meminfo.get("page_tables_kb", 0) / 1024
        m_kstack = meminfo.get("kernel_stack_kb", 0) / 1024
        m_huge_sz = meminfo.get("hugepagesize_kb", 0) // 1024
        m_huge_tot = meminfo.get("hugepages_total", 0)
        m_huge_free = meminfo.get("hugepages_free", 0)

        # DNS & Sysctl
        dns_data = self.d.get("dns", {})
        dns_srv = ", ".join(f"<code>{s}</code>" for s in dns_data.get("dns_servers", [])) or '<span style="color: var(--text-muted);">-</span>'
        dns_dom = ", ".join(f"<code>{d}</code>" for d in dns_data.get("domains", [])) or '<span style="color: var(--text-muted);">-</span>'
        dns_proto = " ".join(dns_data.get("protocols", [])) or '<span style="color: var(--text-muted);">-</span>'

        sysctl_data = self.d.get("sysctl", {})
        sysctl_rows = ""
        for k, v in sysctl_data.items():
            sysctl_rows += f"""
            <div class="kv-row">
                <span class="kv-key"><code>{k}</code></span>
                <span class="kv-val"><strong style="color: #38bdf8;">{v}</strong></span>
            </div>
            """

        # Log & Crash Audit Badges
        audit = self.d.get("log_audit", {})
        oom_cnt = audit.get("oom_count", 0)
        seg_cnt = audit.get("segfault_count", 0)
        io_cnt = audit.get("io_error_count", 0)
        oom_badge = f'<span class="badge badge-danger">⚠️ {oom_cnt} OOM Events</span>' if oom_cnt > 0 else '<span class="badge badge-success">✅ 0 OOM Detected</span>'
        seg_badge = f'<span class="badge badge-warning">⚠️ {seg_cnt} Segfaults</span>' if seg_cnt > 0 else '<span class="badge badge-success">✅ 0 Segfaults</span>'
        io_badge = f'<span class="badge badge-danger">⚠️ {io_cnt} I/O Errors</span>' if io_cnt > 0 else '<span class="badge badge-success">✅ 0 I/O Errors</span>'

        # Overview Security & Ops Checklist
        checklist_items = [
            ("SSH Daemon Hardening", "포트 12123 비밀번호 인증 차단", pwd_auth != "yes"),
            ("Filesystem Inodes", "모든 파티션 Inode 가용량 정상", not any(d.get("iuse_num", 0) >= 85 for d in self.d["disks"])),
            ("Core Services (Systemd)", f"실패 서비스 0건 ({len(self.d['failed_units'])}개 실패)", len(self.d["failed_units"]) == 0),
            ("Kernel Stability", f"OOM/Panic/Crash 없음 ({oom_cnt + io_cnt}건 감지)", oom_cnt == 0 and io_cnt == 0),
            ("DNS & Network Resolution", "VPC DNS 리졸버 정상 설정", bool(dns_data.get("dns_servers"))),
            ("System Timers", f"주요 백그라운드 타이머 정상 ({len(timers_list)}개 활성)", len(timers_list) > 0),
        ]
        checklist_html = ""
        for title_en, title_ko, is_ok in checklist_items:
            chk_badge = '<span class="badge badge-success">PASS</span>' if is_ok else '<span class="badge badge-warning">CHECK</span>'
            chk_icon = '✅' if is_ok else '⚠️'
            checklist_html += f"""
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; background: var(--bg-card); border-radius: 6px; border: 1px solid var(--border-sub); font-size: 0.85rem;">
                <div>
                    <div>{chk_icon} <strong>{title_en}</strong></div>
                    <div style="color: var(--text-muted); font-size: 0.78rem; margin-top: 2px;">{title_ko}</div>
                </div>
                {chk_badge}
            </div>
            """

        mem = self.d["memory"]
        sys_info = self.d["system"]
        aws_info = self.d["aws"]

        aws_badge = f'<span class="badge badge-primary">AWS EC2 ({aws_info.get("instance_type", "EC2")})</span>' if aws_info.get("is_ec2") else ''
        aws_logo_html = ""
        if aws_info.get("is_ec2"):
            aws_logo_html = """
            <div class="platform-logo-box" title="Cloud Platform: Amazon Web Services (AWS)">
                <svg viewBox="0 0 16 16" width="34" height="34" xmlns="http://www.w3.org/2000/svg">
                    <path fill="var(--text-main)" d="M4.51 7.687c0 .197.02.357.058.475.042.117.096.245.17.384a.233.233 0 01.037.123c0 .053-.032.107-.1.16l-.336.224a.255.255 0 01-.138.048c-.054 0-.107-.026-.16-.074a1.652 1.652 0 01-.192-.251 4.137 4.137 0 01-.165-.315c-.415.491-.936.737-1.564.737-.447 0-.804-.129-1.064-.385-.261-.256-.394-.598-.394-1.025 0-.454.16-.822.484-1.1.325-.278.756-.416 1.304-.416.18 0 .367.016.564.042.197.027.4.07.612.118v-.39c0-.406-.085-.689-.25-.854-.17-.166-.458-.246-.868-.246-.186 0-.377.022-.574.07a4.23 4.23 0 00-.575.181 1.525 1.525 0 01-.186.07.326.326 0 01-.085.016c-.075 0-.112-.054-.112-.166v-.262c0-.085.01-.15.037-.186a.399.399 0 01.15-.113c.185-.096.409-.176.67-.24.26-.07.537-.101.83-.101.633 0 1.096.144 1.394.432.293.288.442.726.442 1.314v1.73h.01zm-2.161.811c.175 0 .356-.032.548-.096.191-.064.362-.182.505-.342a.848.848 0 00.181-.341c.032-.129.054-.283.054-.465V7.03a4.43 4.43 0 00-.49-.09 3.996 3.996 0 00-.5-.033c-.357 0-.618.07-.793.214-.176.144-.26.347-.26.614 0 .25.063.437.196.566.128.133.314.197.559.197zm4.273.577c-.096 0-.16-.016-.202-.054-.043-.032-.08-.106-.112-.208l-1.25-4.127a.938.938 0 01-.049-.214c0-.085.043-.133.128-.133h.522c.1 0 .17.016.207.053.043.032.075.107.107.208l.894 3.535.83-3.535c.026-.106.058-.176.1-.208a.365.365 0 01.214-.053h.425c.102 0 .17.016.213.053.043.032.08.107.101.208l.841 3.578.92-3.578a.458.458 0 01.107-.208.346.346 0 01.208-.053h.495c.085 0 .133.043.133.133 0 .027-.006.054-.01.086a.76.76 0 01-.038.133l-1.283 4.127c-.032.107-.069.177-.111.209a.34.34 0 01-.203.053h-.457c-.101 0-.17-.016-.213-.053-.043-.038-.08-.107-.101-.214L8.213 5.37l-.82 3.439c-.026.107-.058.176-.1.213-.043.038-.118.054-.213.054h-.458zm6.838.144a3.51 3.51 0 01-.82-.096c-.266-.064-.473-.134-.612-.214-.085-.048-.143-.101-.165-.15a.378.378 0 01-.031-.149v-.272c0-.112.042-.166.122-.166a.3.3 0 01.096.016c.032.011.08.032.133.054.18.08.378.144.585.187.213.042.42.064.633.064.336 0 .596-.059.777-.176a.575.575 0 00.277-.508.52.52 0 00-.144-.373c-.095-.102-.276-.193-.537-.278l-.772-.24c-.388-.123-.676-.305-.851-.545a1.275 1.275 0 01-.266-.774c0-.224.048-.422.143-.593.096-.17.224-.32.384-.438.16-.122.34-.213.553-.277.213-.064.436-.091.67-.091.118 0 .24.005.357.021.122.016.234.038.346.06.106.026.208.052.303.085.096.032.17.064.224.096a.46.46 0 01.16.133.289.289 0 01.047.176v.251c0 .112-.042.171-.122.171a.552.552 0 01-.202-.064 2.427 2.427 0 00-1.022-.208c-.303 0-.543.048-.708.15-.165.1-.25.256-.25.475 0 .149.053.277.16.379.106.101.303.202.585.293l.756.24c.383.123.66.294.825.513.165.219.244.47.244.748 0 .23-.047.437-.138.619a1.436 1.436 0 01-.388.47c-.165.133-.362.23-.591.299-.24.075-.49.112-.761.112z"/>
                    <g fill="#FF9900" fill-rule="evenodd" clip-rule="evenodd">
                        <path d="M14.465 11.813c-1.75 1.297-4.294 1.986-6.481 1.986-3.065 0-5.827-1.137-7.913-3.027-.165-.15-.016-.353.18-.235 2.257 1.313 5.04 2.109 7.92 2.109 1.941 0 4.075-.406 6.039-1.239.293-.133.543.192.255.406z"/>
                        <path d="M15.194 10.98c-.223-.287-1.479-.138-2.048-.069-.17.022-.197-.128-.043-.24 1-.705 2.645-.502 2.836-.267.192.24-.053 1.89-.99 2.68-.143.123-.281.06-.218-.1.213-.53.687-1.72.463-2.003z"/>
                    </g>
                </svg>
            </div>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOSReport Analysis - {sys_info.get('hostname', 'Server')}</title>
    <style>
        :root {{
            --bg-body: #0b0f19;
            --bg-card: #131b2e;
            --bg-card-hover: #19233c;
            --bg-card-sub: rgba(15, 23, 42, 0.6);
            --border: #1e293b;
            --border-sub: rgba(255, 255, 255, 0.05);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --primary-glow: rgba(56, 189, 248, 0.15);
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --purple: #a855f7;
            --hero-bg: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.9) 100%);
            --hero-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
            --code-bg: rgba(255, 255, 255, 0.08);
            --code-text: #e2e8f0;
            --log-bg: #060911;
            --log-text: #e2e8f0;
            --search-bg: rgba(15, 23, 42, 0.8);
            --search-text: #fff;
            --btn-bg: rgba(255, 255, 255, 0.06);
            --btn-border: rgba(255, 255, 255, 0.15);
            --btn-text: #f1f5f9;
            --btn-hover: rgba(255, 255, 255, 0.12);
            --th-bg: rgba(255, 255, 255, 0.03);
            --progress-bg: rgba(255, 255, 255, 0.08);
        }}

        body.light-mode {{
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --bg-card-hover: #f1f5f9;
            --bg-card-sub: #f8fafc;
            --border: #e2e8f0;
            --border-sub: rgba(0, 0, 0, 0.06);
            --text-main: #0f172a;
            --text-muted: #64748b;
            --primary: #0284c7;
            --primary-glow: rgba(2, 132, 199, 0.08);
            --success: #059669;
            --warning: #d97706;
            --danger: #dc2626;
            --purple: #9333ea;
            --hero-bg: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            --hero-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.06);
            --code-bg: #f1f5f9;
            --code-text: #0f172a;
            --log-bg: #0f172a;
            --log-text: #f8fafc;
            --search-bg: #ffffff;
            --search-text: #0f172a;
            --btn-bg: #f1f5f9;
            --btn-border: #cbd5e1;
            --btn-text: #0f172a;
            --btn-hover: #e2e8f0;
            --th-bg: #f1f5f9;
            --progress-bg: #e2e8f0;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            transition: background-color 0.2s ease, border-color 0.2s ease, color 0.2s ease;
        }}
        body {{
            background-color: var(--bg-body);
            color: var(--text-main);
            padding: 24px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{
            max-width: 1300px;
            margin: 0 auto;
        }}

        /* Header Hero */
        .hero {{
            background: var(--hero-bg);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px 30px;
            margin-bottom: 24px;
            box-shadow: var(--hero-shadow);
            position: relative;
            overflow: hidden;
        }}
        .hero::before {{
            content: "";
            position: absolute;
            top: -50%;
            right: -20%;
            width: 350px;
            height: 350px;
            background: radial-gradient(circle, var(--primary-glow) 0%, transparent 70%);
            pointer-events: none;
        }}
        .hero-top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 16px;
        }}
        .platform-logo-box {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 50px;
            height: 50px;
            border-radius: 12px;
            background: rgba(255, 153, 0, 0.08);
            border: 1px solid rgba(255, 153, 0, 0.28);
            box-shadow: 0 2px 8px rgba(255, 153, 0, 0.12);
            flex-shrink: 0;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        .platform-logo-box:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(255, 153, 0, 0.24);
            border-color: rgba(255, 153, 0, 0.5);
        }}
        .host-title {{
            font-size: 1.75rem;
            font-weight: 800;
            color: var(--text-main);
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .pulse-dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: {status_color};
            box-shadow: 0 0 10px {status_color};
        }}
        .meta-pills {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
        .meta-pill {{
            background: var(--btn-bg);
            border: 1px solid var(--border);
            padding: 4px 12px;
            border-radius: 20px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        /* Top Controls Toolbar */
        .hero-right {{
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 10px;
        }}
        .control-toolbar {{
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .action-btn {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: var(--btn-bg);
            border: 1px solid var(--btn-border);
            color: var(--btn-text);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            user-select: none;
        }}
        .action-btn:hover {{
            background: var(--btn-hover);
            transform: translateY(-1px);
            border-color: var(--primary);
        }}
        .status-summary-box {{
            text-align: right;
        }}
        .status-label {{
            font-size: 0.78rem;
            font-weight: 700;
            color: var(--text-muted);
            letter-spacing: 0.5px;
        }}
        .status-score {{
            font-size: 1.5rem;
            font-weight: 800;
        }}

        /* KPI Cards Grid */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.02);
            transition: all 0.2s ease;
        }}
        .kpi-card:hover {{
            border-color: rgba(56, 189, 248, 0.4);
            transform: translateY(-2px);
        }}
        .kpi-label {{
            font-size: 0.78rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}
        .kpi-value {{
            font-size: 1.6rem;
            font-weight: 700;
            color: var(--text-main);
            margin-bottom: 4px;
        }}
        .kpi-sub {{
            font-size: 0.8rem;
            color: var(--text-muted);
        }}

        /* Navigation Tabs */
        .tabs {{
            display: flex;
            gap: 8px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
            overflow-x: auto;
            padding-bottom: 2px;
        }}
        .tab-btn {{
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 10px 18px;
            font-size: 0.9rem;
            font-weight: 600;
            border-radius: 8px 8px 0 0;
            cursor: pointer;
            transition: all 0.2s ease;
            white-space: nowrap;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .tab-btn:hover {{
            color: var(--text-main);
            background: var(--btn-bg);
        }}
        .tab-btn.active {{
            color: var(--primary);
            background: rgba(56, 189, 248, 0.1);
            border-bottom: 2px solid var(--primary);
        }}

        /* Content Sections */
        .tab-content {{
            display: none;
        }}
        .tab-content.active {{
            display: block;
            animation: fadeIn 0.25s ease-out;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(4px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        /* Layout Grids */
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }}
        @media (max-width: 900px) {{
            .grid-2 {{ grid-template-columns: 1fr; }}
        }}

        /* Cards & Panels */
        .panel {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.02);
        }}
        .panel-title {{
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--text-main);
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .ref-path {{
            font-size: 0.76rem;
            color: var(--text-muted);
            margin-bottom: 16px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: var(--btn-bg);
            border: 1px solid var(--border);
            padding: 3px 10px;
            border-radius: 6px;
            width: fit-content;
        }}
        .ref-path code {{
            font-size: 0.74rem;
            color: var(--primary);
            background: rgba(56, 189, 248, 0.08);
            border: none;
            padding: 1px 4px;
        }}

        .card {{
            background: var(--bg-card-sub);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 16px;
        }}
        .card-danger {{ border-left: 4px solid var(--danger); }}
        .card-warning {{ border-left: 4px solid var(--warning); }}
        .card-success {{ border-left: 4px solid var(--success); }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.3px;
        }}
        .badge-primary {{ background: rgba(56, 189, 248, 0.15); color: var(--primary); }}
        .badge-success {{ background: rgba(16, 185, 129, 0.15); color: var(--success); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.15); color: var(--warning); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.15); color: var(--danger); }}
        .badge-secondary {{ background: rgba(148, 163, 184, 0.15); color: var(--text-muted); }}
        .badge-outline {{ border: 1px solid var(--border); color: var(--text-main); }}

        /* Tables */
        .table-responsive {{
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            text-align: left;
        }}
        th {{
            background: var(--th-bg);
            color: var(--text-muted);
            font-weight: 600;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-sub);
            color: var(--text-main);
        }}
        tr:hover td {{
            background: var(--bg-card-hover);
        }}

        /* Progress Bar */
        .progress-box {{
            background: var(--progress-bg);
            border-radius: 6px;
            height: 7px;
            width: 100%;
            overflow: hidden;
            margin-bottom: 4px;
        }}
        .progress-bar {{
            height: 100%;
            border-radius: 6px;
            transition: width 0.3s ease;
        }}

        /* Code & Pre */
        code {{
            background: var(--code-bg);
            color: var(--code-text);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.85em;
        }}
        .code-sm {{
            font-size: 0.75rem;
        }}
        .log-pre {{
            background: var(--log-bg);
            color: var(--log-text);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.78rem;
            line-height: 1.45;
            max-height: 380px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        /* Search input */
        .search-box {{
            background: var(--search-bg);
            border: 1px solid var(--border);
            color: var(--search-text);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.82rem;
            width: 220px;
        }}
        .search-box:focus {{
            outline: none;
            border-color: var(--primary);
        }}

        /* Key-Value Lists */
        .kv-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-sub);
            font-size: 0.85rem;
        }}
        .kv-key {{ color: var(--text-muted); }}
        .kv-val {{ color: var(--text-main); font-weight: 500; text-align: right; }}

        /* Footer */
        .footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Hero Header -->
        <div class="hero">
            <div class="hero-top">
                <div style="display: flex; align-items: center; gap: 16px;">
                    {aws_logo_html}
                    <div>
                        <div class="host-title">
                            <span class="pulse-dot"></span>
                            {sys_info.get('hostname', 'Server')}
                            {aws_badge}
                        </div>
                        <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 4px;">
                            {sys_info.get('os_distro', 'Linux')} &bull; Kernel {sys_info.get('kernel', '')} &bull; {sys_info.get('arch', '')}
                        </div>
                    </div>
                </div>
                <div class="hero-right">
                    <!-- Top Controls: Theme & Translation -->
                    <div class="control-toolbar">
                        <button id="themeToggleBtn" onclick="toggleTheme()" class="action-btn" title="다크/라이트 모드 전환 (Toggle Dark/Light Mode)">
                            <span id="themeIcon">☀️</span>
                            <span id="themeLabel">라이트 모드</span>
                        </button>
                        <button id="langToggleBtn" onclick="toggleLang()" class="action-btn" title="한글 / 영문 전환 (Switch Language)">
                            <span id="langIcon">🌐</span>
                            <span id="langLabel">English</span>
                        </button>
                        <button onclick="window.print()" class="action-btn" title="PDF 저장 / 인쇄 (Print or Save PDF)">
                            <span>🖨️</span>
                            <span data-i18n="print_btn">PDF / 인쇄</span>
                        </button>
                    </div>
                    <div class="status-summary-box">
                        <div class="status-label" data-i18n="system_status">시스템 건전성 진단</div>
                        <div class="status-score" style="color: {status_color};">
                            <span id="statusText" class="i18n-elem" data-ko="{status_label_ko}" data-en="{status_label_en}">{status_label_ko}</span> ({score}/100)
                        </div>
                    </div>
                </div>
            </div>
            <div class="meta-pills">
                <div class="meta-pill">📁 <strong data-i18n="archive_lbl">아카이브:</strong> {self.d['archive_name']} ({self.d['archive_size_mb']} MB)</div>
                <div class="meta-pill">⏱ <strong data-i18n="uptime_lbl">가동 시간:</strong> {sys_info.get('uptime_human', 'N/A')}</div>
                <div class="meta-pill">📅 <strong data-i18n="collected_lbl">수집 일시:</strong> {self.d.get('manifest', {}).get('start_time', sys_info.get('date', 'N/A'))}</div>
                <div class="meta-pill">⚙️ <strong data-i18n="sos_ver_lbl">SOS 버전:</strong> {self.d.get('manifest', {}).get('version', 'N/A')}</div>
            </div>
        </div>

        <!-- KPI Grid -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label" data-i18n="kpi_cpu_cores">CPU 코어 및 부하</div>
                <div class="kpi-value">{self.d['cpu'].get('cores', 1)} vCPUs</div>
                <div class="kpi-sub"><span data-i18n="kpi_load_avg">평균 부하</span>: <strong>{sys_info.get('load_1m', 0.0):.2f}</strong>, {sys_info.get('load_5m', 0.0):.2f}, {sys_info.get('load_15m', 0.0):.2f}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label" data-i18n="kpi_mem_util">메모리 사용률</div>
                <div class="kpi-value">{mem.get('usage_pct', 0)}%</div>
                <div class="kpi-sub"><span data-i18n="kpi_mem_used">사용</span>: {mem.get('used_mb', 0):.0f} MB / <span data-i18n="kpi_mem_avail">여유</span>: {mem.get('available_mb', 0):.0f} MB</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label" data-i18n="kpi_swap_util">스왑 사용량</div>
                <div class="kpi-value">{mem.get('swap_usage_pct', 0)}%</div>
                <div class="kpi-sub"><span data-i18n="kpi_mem_used">사용</span>: {mem.get('swap_used_mb', 0):.0f} MB / <span data-i18n="kpi_swap_total">전체</span>: {mem.get('swap_total_mb', 0):.0f} MB</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label" data-i18n="kpi_failed_svc">실패한 서비스</div>
                <div class="kpi-value" style="color: {'#ef4444' if self.d['failed_units'] else '#10b981'};">
                    {len(self.d['failed_units'])} <span data-i18n="units_cnt" style="font-size: 1.1rem; font-weight: 600;">개</span>
                </div>
                <div class="kpi-sub" data-i18n="kpi_systemd_status">Systemd 서비스 상태</div>
            </div>
        </div>

        <!-- Tabs Navigation -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('tab-overview', this)" data-i18n="tab_overview">📊 진단 및 개요</button>
            <button class="tab-btn" onclick="switchTab('tab-users', this)"><span data-i18n="tab_users">👤 사용자</span> ({len(self.d.get('users', []))})</button>
            <button class="tab-btn" onclick="switchTab('tab-storage', this)"><span data-i18n="tab_storage">💾 스토리지</span> ({len(self.d['disks'])})</button>
            <button class="tab-btn" onclick="switchTab('tab-memory', this)" data-i18n="tab_memory">🧠 CPU 및 메모리</button>
            <button class="tab-btn" onclick="switchTab('tab-services', this)" data-i18n="tab_services">⚙️ 서비스 및 부팅</button>
            <button class="tab-btn" onclick="switchTab('tab-network', this)"><span data-i18n="tab_network">🌐 네트워크 및 포트</span> ({len(self.d['network']['listening_ports'])})</button>
            <button class="tab-btn" onclick="switchTab('tab-processes', this)" data-i18n="tab_processes">📈 프로세스</button>
            <button class="tab-btn" onclick="switchTab('tab-logs', this)" data-i18n="tab_logs">📜 로그 및 커널</button>
            <button class="tab-btn" onclick="switchTab('tab-raw', this)" data-i18n="tab_raw">🔍 원본 JSON</button>
        </div>

        <!-- TAB 1: OVERVIEW & HEALTH -->
        <div id="tab-overview" class="tab-content active">
            <div class="grid-2">
                <div class="panel">
                    <div class="panel-title" data-i18n="diag_assessment">시스템 진단 평가</div>
                    {make_ref_badge(ref_diag)}
                    {finding_cards}
                </div>
                <div class="panel">
                    <div class="panel-title" data-i18n="host_details">호스트 및 환경 상세</div>
                    {make_ref_badge(ref_host)}
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_hostname">호스트명</span>
                        <span class="kv-val"><code>{sys_info.get('hostname', '')}</code></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_os">운영체제</span>
                        <span class="kv-val">{sys_info.get('os_distro', '')}</span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_kernel">커널 릴리스</span>
                        <span class="kv-val">{sys_info.get('kernel', '')}</span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_arch">하드웨어 아키텍처</span>
                        <span class="kv-val">{sys_info.get('arch', '')}</span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_date">수집 시스템 시각</span>
                        <span class="kv-val">{sys_info.get('date', 'N/A')}</span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_uptime">시스템 가동 시간</span>
                        <span class="kv-val">{sys_info.get('raw_uptime', '')}</span>
                    </div>
                    {f'''
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_aws_id">AWS 인스턴스 ID</span>
                        <span class="kv-val"><code>{aws_info.get('instance_id')}</code></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_aws_type">AWS 인스턴스 타입</span>
                        <span class="kv-val">{aws_info.get('instance_type')}</span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_aws_az">가용 영역 (AZ)</span>
                        <span class="kv-val">{aws_info.get('availability_zone')}</span>
                    </div>
                    ''' if aws_info.get('is_ec2') else ''}
                    {f'''
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_nginx">Nginx 웹 서버</span>
                        <span class="kv-val">{self.d['nginx'].get('version', 'Active')}</span>
                    </div>
                    ''' if self.d['nginx'].get('detected') else ''}
                </div>
            </div>

            <div class="panel" style="margin-top: 16px;">
                <div class="panel-title" data-i18n="checklist_title">🛡️ 시스템 보안 및 인프라 건전성 체크리스트 (Security & Ops Checklist)</div>
                {make_ref_badge(f"{ref_ssh}, {ref_df_inodes}, {ref_dns}")}
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 12px; margin-top: 10px;">
                    {checklist_html}
                </div>
            </div>
        </div>

        <!-- TAB 2: USERS -->
        <div id="tab-users" class="tab-content">
            <div class="panel">
                <div class="panel-title">
                    <span data-i18n="users_title">시스템 계정 및 사용자 권한 목록 (getent passwd / sudoers.d)</span>
                    <input type="text" class="search-box" placeholder="사용자 검색..." data-i18n-placeholder="filter_users" onkeyup="filterTable(this, 'tbl-users')">
                </div>
                {make_ref_badge(ref_users)}
                <div class="table-responsive">
                    <table id="tbl-users">
                        <thead>
                            <tr>
                                <th data-i18n="th_user">사용자 계정</th>
                                <th>UID:GID</th>
                                <th data-i18n="th_type">계정 및 권한 구분</th>
                                <th data-i18n="th_shell">로그인 쉘</th>
                                <th data-i18n="th_home">홈 디렉터리</th>
                                <th data-i18n="th_procs" style="text-align: center;">프로세스</th>
                                <th data-i18n="th_last_login">최근 로그인</th>
                            </tr>
                        </thead>
                        <tbody>
                            {user_rows}
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Recent logins panel (Moved to Users tab) -->
            <div class="panel">
                <div class="panel-title" data-i18n="recent_logins">최근 사용자 로그인 이력 (wtmp)</div>
                {make_ref_badge(ref_logins)}
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th data-i18n="th_user">사용자</th>
                                <th data-i18n="th_session">세션 / TTY</th>
                                <th data-i18n="th_source_ip">접속 IP</th>
                                <th data-i18n="th_login_time">접속 시간 및 상태</th>
                            </tr>
                        </thead>
                        <tbody>
                            {login_rows}
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- SSH Security Audit Panel -->
            <div class="panel">
                <div class="panel-title" data-i18n="ssh_audit_title">🔐 SSH 원격 접근 및 데몬 보안 감사 (sshd -T)</div>
                {make_ref_badge(ref_ssh)}
                <div class="grid-2" style="margin-top: 10px;">
                    <div>
                        <div class="kv-row">
                            <span class="kv-key" data-i18n="kv_ssh_port">SSH 서비스 포트</span>
                            <span class="kv-val"><code style="font-weight: 700; color: #38bdf8;">{ssh_port}</code></span>
                        </div>
                        <div class="kv-row">
                            <span class="kv-key" data-i18n="kv_pwd_auth">비밀번호 인증 (PasswordAuthentication)</span>
                            <span class="kv-val">{pwd_badge}</span>
                        </div>
                        <div class="kv-row">
                            <span class="kv-key" data-i18n="kv_pubkey_auth">공개키 인증 (PubkeyAuthentication)</span>
                            <span class="kv-val">{pub_badge}</span>
                        </div>
                    </div>
                    <div>
                        <div class="kv-row">
                            <span class="kv-key" data-i18n="kv_root_login">루트 로그인 허용 (PermitRootLogin)</span>
                            <span class="kv-val">{root_badge}</span>
                        </div>
                        <div class="kv-row">
                            <span class="kv-key" data-i18n="kv_max_tries">최대 인증 시도 (MaxAuthTries)</span>
                            <span class="kv-val">{ssh_cfg.get('maxauthtries', '6')}</span>
                        </div>
                        <div class="kv-row">
                            <span class="kv-key" data-i18n="kv_client_alive">세션 유지 타임아웃 (ClientAlive)</span>
                            <span class="kv-val">{ssh_cfg.get('clientaliveinterval', '0')}s</span>
                        </div>
                    </div>
                </div>
                {f'''
                <div class="alert alert-warning" style="margin-top: 12px; font-size: 0.85rem;" data-i18n="ssh_warn_advice">
                    ⚠️ <strong>보안 권고:</strong> 배스천 호스트의 포트 {ssh_port}에서 비밀번호 인증이 허용되어 있습니다. 무차별 대입 공격에 대비하여 <code>/etc/ssh/sshd_config</code>에서 <code>PasswordAuthentication no</code>로 변경할 것을 강력히 권장합니다.
                </div>
                ''' if pwd_auth == "yes" else ''}
            </div>
        </div>

        <!-- TAB 3: STORAGE -->
        <div id="tab-storage" class="tab-content">
            <div class="panel">
                <div class="panel-title" data-i18n="block_devices_title">디스크 블록 디바이스 구성 (로컬 및 추가 디스크 - lsblk)</div>
                {make_ref_badge(ref_lsblk)}
                <div class="grid-2">
                    <div>
                        <h4 style="font-size: 0.95rem; margin-bottom: 10px; color: var(--text-main);" data-i18n="local_disks_title">💾 로컬 / 기본 OS 디스크</h4>
                        {local_disk_html}
                    </div>
                    <div>
                        <h4 style="font-size: 0.95rem; margin-bottom: 10px; color: var(--text-main);" data-i18n="additional_disks_title">🗄️ 추가 디스크 (Attached Disks)</h4>
                        {additional_disk_html}
                    </div>
                </div>
            </div>

            <div class="panel">
                <div class="panel-title">
                    <span data-i18n="fs_mounts">파일시스템 마운트 및 디스크 사용량 (df -h)</span>
                    <input type="text" class="search-box" placeholder="마운트 검색..." data-i18n-placeholder="filter_mounts" onkeyup="filterTable(this, 'tbl-disks')">
                </div>
                {make_ref_badge(f"{ref_storage}, {ref_df_inodes}")}
                <div class="table-responsive">
                    <table id="tbl-disks">
                        <thead>
                            <tr>
                                <th data-i18n="th_mount">마운트 경로</th>
                                <th data-i18n="th_fs">파일시스템 / 디바이스</th>
                                <th data-i18n="th_size">전체 용량</th>
                                <th data-i18n="th_used">사용량</th>
                                <th data-i18n="th_avail">여유 공간</th>
                                <th data-i18n="th_use_pct">사용률</th>
                                <th data-i18n="th_inodes">아이노드 (Inodes)</th>
                                <th data-i18n="th_iuse">아이노드 사용률</th>
                            </tr>
                        </thead>
                        <tbody>
                            {disk_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 3: CPU & MEMORY -->
        <div id="tab-memory" class="tab-content">
            <div class="grid-2">
                <div class="panel">
                    <div class="panel-title" data-i18n="cpu_specs">CPU 하드웨어 사양 (lscpu)</div>
                    {make_ref_badge(ref_lscpu)}
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_cpu_model">프로세서 모델</span>
                        <span class="kv-val" style="font-size: 0.8rem;">{self.d['cpu'].get('model', 'Unknown')}</span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_cpu_cores">논리 CPU 코어</span>
                        <span class="kv-val">{self.d['cpu'].get('cores', 1)}</span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_cpu_threads">코어당 스레드</span>
                        <span class="kv-val">{self.d['cpu'].get('threads_per_core', 1)}</span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_cpu_arch">아키텍처</span>
                        <span class="kv-val">{self.d['cpu'].get('architecture', 'x86_64')}</span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_cpu_load">현재 부하 (1분, 5분, 15분)</span>
                        <span class="kv-val">{sys_info.get('load_1m', 0.0):.2f}, {sys_info.get('load_5m', 0.0):.2f}, {sys_info.get('load_15m', 0.0):.2f}</span>
                    </div>
                </div>

                <div class="panel">
                    <div class="panel-title" data-i18n="ram_dist">RAM 및 Swap 메모리 분포</div>
                    {make_ref_badge(ref_mem)}
                    <div style="margin-bottom: 16px;">
                        <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 6px;">
                            <span><span data-i18n="kpi_mem_util">메모리 사용률</span>: <strong>{mem.get('usage_pct', 0)}%</strong></span>
                            <span>{mem.get('used_mb', 0):.0f} MB / {mem.get('total_mb', 0):.0f} MB</span>
                        </div>
                        <div class="progress-box" style="height: 12px; display: flex; background: var(--progress-bg);">
                            <div style="width: {(mem.get('used_mb',0)/mem.get('total_mb',1))*100:.1f}%; background: #38bdf8;" title="Used"></div>
                            <div style="width: {(mem.get('buff_cache_mb',0)/mem.get('total_mb',1))*100:.1f}%; background: #64748b;" title="Buffers & Cache"></div>
                        </div>
                        <div style="display: flex; gap: 14px; font-size: 0.75rem; color: var(--text-muted); margin-top: 6px;">
                            <span><span style="color: #38bdf8;">■</span> <span data-i18n="kpi_mem_used">사용</span> ({mem.get('used_mb',0):.0f} MB)</span>
                            <span><span style="color: #64748b;">■</span> <span data-i18n="kpi_buff_cache">버퍼/캐시</span> ({mem.get('buff_cache_mb',0):.0f} MB)</span>
                            <span><span style="color: #cbd5e1;">■</span> <span data-i18n="kpi_mem_avail">여유</span> ({mem.get('free_mb',0):.0f} MB)</span>
                        </div>
                    </div>

                    <div>
                        <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 6px;">
                            <span><span data-i18n="kpi_swap_util">스왑 사용량</span>: <strong>{mem.get('swap_usage_pct', 0)}%</strong></span>
                            <span>{mem.get('swap_used_mb', 0):.0f} MB / {mem.get('swap_total_mb', 0):.0f} MB</span>
                        </div>
                        <div class="progress-box" style="height: 8px;">
                            <div class="progress-bar" style="width: {mem.get('swap_usage_pct', 0)}%; background: #a855f7;"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Detailed Analysis: proc/cpuinfo & proc/meminfo -->
            <div class="grid-2" style="margin-top: 16px;">
                <div class="panel">
                    <div class="panel-title" data-i18n="cpuinfo_title">🔬 커널 프로세서 아키텍처 및 하드웨어 분석 (/proc/cpuinfo)</div>
                    {make_ref_badge(ref_cpuinfo)}
                    <div class="kv-row">
                        <span class="kv-key">CPU 모델 / 벤더</span>
                        <span class="kv-val"><code class="code-sm">{cpuinfo.get('vendor_id', 'N/A')}</code> &bull; Family {cpuinfo.get('family', 'N/A')} (Model {cpuinfo.get('model', 'N/A')}, Step {cpuinfo.get('stepping', 'N/A')})</span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_microcode">마이크로코드 (Microcode)</span>
                        <span class="kv-val"><code>{cpuinfo.get('microcode', 'N/A')}</code></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_l3_cache">L3 캐시 용량 (Cache Size)</span>
                        <span class="kv-val"><strong style="color: #38bdf8;">{cpuinfo.get('cache_size', 'N/A')}</strong></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="kv_bogomips">BogoMIPS / 주소 체계</span>
                        <span class="kv-val"><code>{cpuinfo.get('bogomips', 'N/A')}</code> &bull; <span style="font-size: 0.78rem; color: var(--text-muted);">{cpuinfo.get('address_sizes', 'N/A')}</span></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key">가상화 / 하이퍼바이저</span>
                        <span class="kv-val">{cpu_virt_badges}</span>
                    </div>
                    <div style="margin-top: 12px;">
                        <div style="font-size: 0.8rem; font-weight: 600; color: var(--text-main); margin-bottom: 6px;" data-i18n="kv_simd_ext">SIMD / 벡터 가속 명령어</div>
                        <div style="line-height: 1.6;">{cpu_simd_badges}</div>
                    </div>
                    <div style="margin-top: 12px;">
                        <div style="font-size: 0.8rem; font-weight: 600; color: var(--text-main); margin-bottom: 6px;" data-i18n="kv_crypto_sec">하드웨어 보안 / 암호화</div>
                        <div style="line-height: 1.6;">{cpu_sec_badges}</div>
                    </div>
                    <div style="margin-top: 12px; border-top: 1px solid var(--border); padding-top: 10px;">
                        <div style="font-size: 0.8rem; font-weight: 600; color: var(--text-main); margin-bottom: 6px;" data-i18n="kv_hw_bugs">커널 감지 하드웨어 취약점 (Errata / Bugs)</div>
                        <div style="line-height: 1.6;">{cpu_bug_badges}</div>
                    </div>
                </div>

                <div class="panel">
                    <div class="panel-title" data-i18n="meminfo_title">🧪 커널 메모리 할당 및 가상 메모리 심층 분석 (/proc/meminfo)</div>
                    {make_ref_badge(ref_meminfo)}
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; margin-bottom: 14px;">
                        <div style="background: var(--bg-hover); padding: 8px 10px; border-radius: 8px; border: 1px solid var(--border);">
                            <div style="font-size: 0.7rem; color: var(--text-muted);" data-i18n="kpi_real_avail">실질 가용 메모리</div>
                            <div style="font-size: 1rem; font-weight: 700; color: #10b981; margin-top: 2px;">{m_avail_mb:.0f} MB</div>
                            <div style="font-size: 0.68rem; color: var(--text-muted);">{m_avail_pct}% of RAM</div>
                        </div>
                        <div style="background: var(--bg-hover); padding: 8px 10px; border-radius: 8px; border: 1px solid var(--border);">
                            <div style="font-size: 0.7rem; color: var(--text-muted);" data-i18n="kpi_kernel_slab">커널 슬랩 (Slab)</div>
                            <div style="font-size: 1rem; font-weight: 700; color: #38bdf8; margin-top: 2px;">{m_slab_mb:.0f} MB</div>
                            <div style="font-size: 0.68rem; color: var(--text-muted);">Reclaim: {m_srec_mb:.0f} MB</div>
                        </div>
                        <div style="background: var(--bg-hover); padding: 8px 10px; border-radius: 8px; border: 1px solid var(--border);">
                            <div style="font-size: 0.7rem; color: var(--text-muted);" data-i18n="kpi_overcommit">메모리 커밋</div>
                            <div style="font-size: 1rem; font-weight: 700; color: #f59e0b; margin-top: 2px;">{m_commit_pct}%</div>
                            <div style="font-size: 0.68rem; color: var(--text-muted);">{m_commit_mb:.0f} / {m_limit_mb:.0f} MB</div>
                        </div>
                        <div style="background: var(--bg-hover); padding: 8px 10px; border-radius: 8px; border: 1px solid var(--border);">
                            <div style="font-size: 0.7rem; color: var(--text-muted);" data-i18n="kpi_dirty_write">디스크 쓰기 대기</div>
                            <div style="font-size: 1rem; font-weight: 700; color: var(--text-main); margin-top: 2px;">{m_dirty_mb:.1f} MB</div>
                            <div style="font-size: 0.68rem; color: var(--text-muted);">Writeback: {m_wb_mb:.1f} MB</div>
                        </div>
                    </div>

                    <div class="kv-row">
                        <span class="kv-key" data-i18n="mem_anon_title">익명 메모리 (Anon - Active / Inactive)</span>
                        <span class="kv-val"><strong>{m_act_anon:.0f} MB</strong> / <span style="color: var(--text-muted);">{m_inact_anon:.0f} MB</span></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="mem_file_title">파일 캐시 (File - Active / Inactive)</span>
                        <span class="kv-val"><strong>{m_act_file:.0f} MB</strong> / <span style="color: var(--text-muted);">{m_inact_file:.0f} MB</span></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="mem_kernel_title">커널 관리 (PageTables / KernelStack)</span>
                        <span class="kv-val">PageTables: <code>{m_pgtables:.1f} MB</code> &bull; Stack: <code>{m_kstack:.1f} MB</code></span>
                    </div>
                    <div class="kv-row">
                        <span class="kv-key" data-i18n="mem_hugepages_title">HugePages 구성</span>
                        <span class="kv-val">{m_huge_sz} MB <span style="color: var(--text-muted); font-size: 0.78rem;">(Total: {m_huge_tot}, Free: {m_huge_free})</span></span>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 4: SERVICES -->
        <div id="tab-services" class="tab-content">
            <div class="grid-2">
                <div class="panel">
                    <div class="panel-title"><span data-i18n="failed_units_title">실패한 Systemd 유닛</span> ({len(self.d['failed_units'])})</div>
                    {make_ref_badge(ref_failed_units)}
                    {failed_rows}
                </div>

                <div class="panel">
                    <div class="panel-title" data-i18n="boot_blame_title">부팅 지연 서비스 순위 (systemd-analyze blame)</div>
                    {make_ref_badge(ref_blame)}
                    <div style="max-height: 400px; overflow-y: auto;">
                        {blame_rows}
                    </div>
                </div>
            </div>

            <!-- Crontab & Scheduled Jobs Panel -->
            <div class="panel" style="margin-top: 16px;">
                <div class="panel-title">
                    <span><span data-i18n="crontab_title">📅 Crontab 및 예약 작업 (Crontab & Scheduled Jobs)</span> ({total_cron_count})</span>
                    <input type="text" class="search-box" placeholder="크론 작업 검색..." data-i18n-placeholder="filter_crons" onkeyup="filterTable(this, 'tbl-crons')">
                </div>
                {make_ref_badge(ref_crontab)}
                <div class="table-responsive">
                    <table id="tbl-crons">
                        <thead>
                            <tr>
                                <th data-i18n="th_cron_user">구분 / 사용자</th>
                                <th data-i18n="th_cron_schedule">실행 주기 (Schedule)</th>
                                <th data-i18n="th_cron_cmd">실행 명령어 (Command)</th>
                                <th data-i18n="th_cron_desc">설명 / 주석 (Description)</th>
                                <th data-i18n="th_cron_source">출처 파일 (Source)</th>
                            </tr>
                        </thead>
                        <tbody>
                            {cron_rows}
                        </tbody>
                    </table>
                </div>

                <!-- Periodic Cron Scripts (/etc/cron.*) -->
                <div style="margin-top: 18px; border-top: 1px solid var(--border-color); padding-top: 14px;">
                    <h4 style="font-size: 0.9rem; margin-bottom: 10px; color: var(--text-main);" data-i18n="periodic_cron_title">📁 주기적 실행 스크립트 디렉터리 (/etc/cron.*)</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px;">
                        <div style="background: var(--bg-hover); padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border-color);">
                            <div style="font-weight: 600; font-size: 0.82rem; color: var(--text-main); margin-bottom: 6px;">⏱️ /etc/cron.hourly ({len(periodic_hourly)})</div>
                            <div>{badges_hourly}</div>
                        </div>
                        <div style="background: var(--bg-hover); padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border-color);">
                            <div style="font-weight: 600; font-size: 0.82rem; color: var(--text-main); margin-bottom: 6px;">📅 /etc/cron.daily ({len(periodic_daily)})</div>
                            <div>{badges_daily}</div>
                        </div>
                        <div style="background: var(--bg-hover); padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border-color);">
                            <div style="font-weight: 600; font-size: 0.82rem; color: var(--text-main); margin-bottom: 6px;">🗓️ /etc/cron.weekly ({len(periodic_weekly)})</div>
                            <div>{badges_weekly}</div>
                        </div>
                        <div style="background: var(--bg-hover); padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border-color);">
                            <div style="font-weight: 600; font-size: 0.82rem; color: var(--text-main); margin-bottom: 6px;">📆 /etc/cron.monthly ({len(periodic_monthly)})</div>
                            <div>{badges_monthly}</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Active Timers Panel -->
            <div class="panel" style="margin-top: 16px;">
                <div class="panel-title">
                    <span><span data-i18n="timers_title">⏰ 백그라운드 스케줄러 타이머 (systemctl list-timers)</span> ({len(self.d.get('timers', []))})</span>
                    <input type="text" class="search-box" placeholder="타이머 검색..." data-i18n-placeholder="filter_timers" onkeyup="filterTable(this, 'tbl-timers')">
                </div>
                {make_ref_badge(ref_timers)}
                <div class="table-responsive">
                    <table id="tbl-timers">
                        <thead>
                            <tr>
                                <th data-i18n="th_timer_unit">타이머 유닛 (.timer)</th>
                                <th data-i18n="th_timer_next">다음 실행 시각 (Next)</th>
                                <th data-i18n="th_timer_left">남은 대기 시간 (Left)</th>
                                <th data-i18n="th_timer_activates">트리거 대상 서비스 (Activates)</th>
                            </tr>
                        </thead>
                        <tbody>
                            {timer_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 5: NETWORK -->
        <div id="tab-network" class="tab-content">
            <div class="grid-2">
                <div class="panel">
                    <div class="panel-title" data-i18n="net_ifaces_title">네트워크 인터페이스</div>
                    {make_ref_badge(ref_net)}
                    {iface_cards}
                    <div style="margin-top: 14px;">
                        <h4 style="font-size: 0.9rem; margin-bottom: 8px; color: var(--text-main);" data-i18n="routes_title">라우팅 테이블 요약</h4>
                        <pre class="log-pre" style="max-height: 180px;">{chr(10).join(self.d['network']['routes'])}</pre>
                    </div>
                </div>

                <div class="panel">
                    <div class="panel-title">
                        <span data-i18n="ports_title">활성 리스닝 포트 (netstat)</span>
                        <input type="text" class="search-box" placeholder="포트 검색..." data-i18n-placeholder="filter_ports" onkeyup="filterTable(this, 'tbl-ports')">
                    </div>
                    {make_ref_badge(ref_ports)}
                    <div class="table-responsive">
                        <table id="tbl-ports">
                            <thead>
                                <tr>
                                    <th data-i18n="th_proto">프로토콜</th>
                                    <th data-i18n="th_port">포트</th>
                                    <th data-i18n="th_binding">바인딩 주소</th>
                                    <th data-i18n="th_prog">프로세스 / 프로그램</th>
                                </tr>
                            </thead>
                            <tbody>
                                {port_rows}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Active Connections & Sysctl Grid -->
            <div class="grid-2" style="margin-top: 16px;">
                <div class="panel">
                    <div class="panel-title">
                        <span><span data-i18n="connections_title">🔗 다른 서버 활성 네트워크 연결 (Active Connections)</span> ({len(remote_conns)})</span>
                        <input type="text" class="search-box" placeholder="연결 검색..." data-i18n-placeholder="filter_connections" onkeyup="filterTable(this, 'tbl-connections')">
                    </div>
                    {make_ref_badge(ref_connections)}
                    <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                        <table id="tbl-connections">
                            <thead>
                                <tr>
                                    <th data-i18n="th_proto">프로토콜</th>
                                    <th data-i18n="th_conn_type">구분</th>
                                    <th data-i18n="th_conn_local">로컬 주소</th>
                                    <th data-i18n="th_conn_foreign">원격 서버 주소</th>
                                    <th data-i18n="th_conn_state">상태</th>
                                    <th data-i18n="th_prog">프로세스 / 프로그램</th>
                                </tr>
                            </thead>
                            <tbody>
                                {conn_rows}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="panel">
                    <div class="panel-title" data-i18n="sysctl_title">⚡ 핵심 커널 네트워크 & 메모리 튜닝 (sysctl)</div>
                    {make_ref_badge(ref_sysctl)}
                    {sysctl_rows}
                </div>
            </div>
        </div>

        <!-- TAB 6: PROCESSES -->
        <div id="tab-processes" class="tab-content">
            <div class="grid-2">
                <div class="panel">
                    <div class="panel-title" data-i18n="top_cpu_title">CPU 사용량 상위 프로세스</div>
                    {make_ref_badge(ref_procs)}
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th data-i18n="th_pid">PID</th>
                                    <th data-i18n="th_user">사용자</th>
                                    <th>%CPU</th>
                                    <th>%MEM</th>
                                    <th data-i18n="th_cmd">실행 명령어</th>
                                </tr>
                            </thead>
                            <tbody>
                                {cpu_proc_rows}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="panel">
                    <div class="panel-title" data-i18n="top_mem_title">메모리 사용량 상위 프로세스</div>
                    {make_ref_badge(ref_procs)}
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th data-i18n="th_pid">PID</th>
                                    <th data-i18n="th_user">사용자</th>
                                    <th>%CPU</th>
                                    <th>%MEM</th>
                                    <th data-i18n="th_cmd">실행 명령어</th>
                                </tr>
                            </thead>
                            <tbody>
                                {mem_proc_rows}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="panel">
                <div class="panel-title">
                    <span><span data-i18n="all_procs_title">활성 프로세스 (자원 점유 상위)</span> ({len(self.d['processes']['all'])})</span>
                    <input type="text" class="search-box" placeholder="프로세스 검색..." data-i18n-placeholder="filter_procs" onkeyup="filterTable(this, 'tbl-all-procs')">
                </div>
                {make_ref_badge(ref_procs)}
                <div class="table-responsive">
                    <table id="tbl-all-procs">
                        <thead>
                            <tr>
                                <th data-i18n="th_pid">PID</th>
                                <th data-i18n="th_user">사용자</th>
                                <th>%CPU</th>
                                <th>%MEM</th>
                                <th data-i18n="th_stat">상태</th>
                                <th data-i18n="th_cmd">실행 명령어</th>
                            </tr>
                        </thead>
                        <tbody>
                            {all_proc_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 7: LOGS & KERNEL -->
        <div id="tab-logs" class="tab-content">
            <div class="card" style="margin-bottom: 16px; background: var(--bg-card-sub); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <div>
                    <strong style="font-size: 0.95rem; color: var(--text-main);" data-i18n="anomaly_header">🔍 커널 오류 & 비정상 이벤트 자동 스캐너</strong>
                    <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 2px;" data-i18n="anomaly_desc">OOM Killer, 세그멘테이션 폴트, 블록 디바이스 I/O 에러 감지 결과</div>
                </div>
                <div style="display: flex; gap: 8px;">
                    {oom_badge}
                    {seg_badge}
                    {io_badge}
                </div>
            </div>

            <div class="panel">
                <div class="panel-title" data-i18n="dmesg_title">커널 경고 및 주요 이벤트 (dmesg)</div>
                {make_ref_badge(ref_dmesg)}
                <pre class="log-pre">{dmesg_html}</pre>
            </div>
            <div class="panel">
                <div class="panel-title" data-i18n="journal_title">Systemd 부팅 저널 경고 및 오류 (journalctl)</div>
                {make_ref_badge(ref_journal)}
                <pre class="log-pre">{journal_html}</pre>
            </div>
        </div>

        <!-- TAB 8: RAW JSON -->
        <div id="tab-raw" class="tab-content">
            <div class="panel">
                <div class="panel-title" data-i18n="raw_json_title">파싱된 진단 JSON 원본 데이터</div>
                {make_ref_badge(ref_json)}
                <pre class="log-pre" style="max-height: 600px;">{json_dump}</pre>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            Generated by <strong>SOSReport Python Analyzer</strong> &bull; ShareTreats Infrastructure Operations &bull; {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </div>
    </div>

    <script>
        const i18n = {{
            ko: {{
                theme_light: "라이트 모드",
                theme_dark: "다크 모드",
                lang_btn: "English",
                print_btn: "PDF / 인쇄",
                system_status: "시스템 건전성 진단",
                status_healthy: "정상",
                status_attention: "점검 필요",
                status_critical: "위험",
                archive_lbl: "아카이브:",
                uptime_lbl: "가동 시간:",
                collected_lbl: "수집 일시:",
                sos_ver_lbl: "SOS 버전:",
                kpi_cpu_cores: "CPU 코어 및 부하",
                kpi_load_avg: "평균 부하",
                kpi_mem_util: "메모리 사용률",
                kpi_mem_used: "사용",
                kpi_mem_avail: "여유",
                kpi_buff_cache: "버퍼/캐시",
                kpi_swap_util: "스왑 사용량",
                kpi_swap_total: "전체",
                kpi_failed_svc: "실패한 서비스",
                kpi_systemd_status: "Systemd 서비스 상태",
                units_cnt: "개",
                tab_overview: "📊 진단 및 개요",
                tab_users: "👤 사용자",
                tab_storage: "💾 스토리지",
                tab_memory: "🧠 CPU 및 메모리",
                tab_services: "⚙️ 서비스 및 부팅",
                tab_network: "🌐 네트워크 및 포트",
                tab_processes: "📈 프로세스",
                tab_logs: "📜 로그 및 커널",
                tab_raw: "🔍 원본 JSON",
                diag_assessment: "시스템 진단 종합 평가",
                host_details: "호스트 및 환경 상세",
                recent_logins: "최근 사용자 로그인 이력 (wtmp)",
                users_title: "시스템 계정 및 사용자 권한 목록 (getent passwd / sudoers.d)",
                local_disks_title: "💾 로컬 / 기본 OS 디스크",
                additional_disks_title: "🗄️ 추가 디스크 (Attached Disks)",
                no_additional_disks: "없음 (None)",
                no_additional_disks_sub: "루트 OS 디스크 외에 별도로 연결된 추가 블록 볼륨이 없습니다.",
                block_devices_title: "디스크 블록 디바이스 구성 (로컬 및 추가 디스크 - lsblk)",
                badge_local_disk: "로컬 / OS 디스크",
                badge_extra_vol: "추가 볼륨",
                partitions_layout: "파티션 구성:",
                disk_mount_role: "용도 / 마운트:",
                unmounted_data: "미마운트 / 데이터 (Unmounted)",
                no_local_disk: "로컬 디스크 정보 없음",
                type_regular: "일반 사용자",
                type_system: "시스템 계정",
                has_sudo_priv: "관리자 권한 포함",
                type_root: "최고 관리자 (Root)",
                th_shell: "로그인 쉘",
                th_home: "홈 디렉터리",
                th_procs: "프로세스",
                th_last_login: "최근 로그인",
                th_type: "계정 및 권한 구분",
                fs_mounts: "파일시스템 마운트 및 디스크 사용량 (df -h)",
                cpu_specs: "CPU 하드웨어 사양 (lscpu)",
                ram_dist: "RAM 및 Swap 메모리 분포",
                failed_units_title: "실패한 Systemd 유닛",
                boot_blame_title: "부팅 지연 서비스 순위 (systemd-analyze blame)",
                net_ifaces_title: "네트워크 인터페이스",
                routes_title: "라우팅 테이블 요약",
                ports_title: "활성 리스닝 포트 (netstat)",
                top_cpu_title: "CPU 사용량 상위 프로세스",
                top_mem_title: "메모리 사용량 상위 프로세스",
                all_procs_title: "활성 프로세스 (자원 점유 상위)",
                dmesg_title: "커널 경고 및 주요 이벤트 (dmesg)",
                journal_title: "Systemd 부팅 저널 경고 및 오류 (journalctl)",
                raw_json_title: "파싱된 진단 JSON 원본 데이터",
                kv_hostname: "호스트명",
                kv_os: "운영체제",
                kv_kernel: "커널 릴리스",
                kv_arch: "하드웨어 아키텍처",
                kv_date: "수집 시스템 시각",
                kv_uptime: "시스템 가동 시간",
                kv_aws_id: "AWS 인스턴스 ID",
                kv_aws_type: "AWS 인스턴스 타입",
                kv_aws_az: "가용 영역 (AZ)",
                kv_nginx: "Nginx 웹 서버",
                kv_cpu_model: "프로세서 모델",
                kv_cpu_cores: "논리 CPU 코어",
                kv_cpu_threads: "코어당 스레드",
                kv_cpu_arch: "아키텍처",
                kv_cpu_load: "현재 부하 (1분, 5분, 15분)",
                th_mount: "마운트 경로",
                th_fs: "파일시스템 / 디바이스",
                th_size: "전체 용량",
                th_used: "사용량",
                th_avail: "여유 공간",
                th_use_pct: "사용률",
                th_user: "사용자",
                th_session: "세션 / TTY",
                th_source_ip: "접속 IP",
                th_login_time: "접속 시간 및 상태",
                th_proto: "프로토콜",
                th_port: "포트",
                th_binding: "바인딩 주소",
                th_prog: "프로세스 / 프로그램",
                th_stat: "상태",
                th_pid: "PID",
                th_cmd: "실행 명령어",
                action_label: "권장 조치:",
                ref_source: "참조 파일:",
                filter_mounts: "마운트 검색...",
                filter_ports: "포트 검색...",
                filter_procs: "프로세스 검색...",
                filter_users: "사용자 검색...",
                checklist_title: "🛡️ 시스템 보안 및 인프라 건전성 체크리스트 (Security & Ops Checklist)",
                ssh_audit_title: "🔐 SSH 원격 접근 및 데몬 보안 감사 (sshd -T)",
                kv_ssh_port: "SSH 서비스 포트",
                kv_pwd_auth: "비밀번호 인증 (PasswordAuthentication)",
                kv_pubkey_auth: "공개키 인증 (PubkeyAuthentication)",
                kv_root_login: "루트 로그인 허용 (PermitRootLogin)",
                kv_max_tries: "최대 인증 시도 (MaxAuthTries)",
                kv_client_alive: "세션 유지 타임아웃 (ClientAlive)",
                badge_enabled_warn: "⚠️ 활성화됨 (위험)",
                badge_disabled_safe: "✅ 비활성화됨 (안전)",
                ssh_warn_advice: "⚠️ 보안 권고: 배스천 호스트에서 비밀번호 인증이 허용되어 있습니다. 무차별 대입 공격에 대비하여 /etc/ssh/sshd_config에서 PasswordAuthentication no로 변경할 것을 강력히 권장합니다.",
                th_inodes: "아이노드 (Inodes)",
                th_iuse: "아이노드 사용률",
                timers_title: "⏰ 백그라운드 스케줄러 타이머 (systemctl list-timers)",
                filter_timers: "타이머 검색...",
                th_timer_unit: "타이머 유닛 (.timer)",
                th_timer_next: "다음 실행 시각 (Next)",
                th_timer_left: "남은 대기 시간 (Left)",
                th_timer_activates: "트리거 대상 서비스 (Activates)",
                no_timers: "등록된 시스템 타이머가 없습니다.",
                crontab_title: "📅 Crontab 및 예약 작업 (Crontab & Scheduled Jobs)",
                filter_crons: "크론 작업 검색...",
                th_cron_user: "구분 / 사용자",
                th_cron_schedule: "실행 주기 (Schedule)",
                th_cron_cmd: "실행 명령어 (Command)",
                th_cron_desc: "설명 / 주석 (Description)",
                th_cron_source: "출처 파일 (Source)",
                no_crons: "등록된 Crontab 예약 작업이 없습니다.",
                periodic_cron_title: "📁 주기적 실행 스크립트 디렉터리 (/etc/cron.*)",
                none_text: "없음 (None)",
                cpuinfo_title: "🔬 커널 프로세서 아키텍처 및 하드웨어 분석 (/proc/cpuinfo)",
                meminfo_title: "🧪 커널 메모리 할당 및 가상 메모리 심층 분석 (/proc/meminfo)",
                kv_microcode: "마이크로코드 (Microcode)",
                kv_l3_cache: "L3 캐시 용량 (Cache Size)",
                kv_bogomips: "BogoMIPS / 주소 체계",
                kv_simd_ext: "SIMD / 벡터 가속 명령어",
                kv_crypto_sec: "하드웨어 보안 / 암호화",
                kv_hw_bugs: "커널 감지 하드웨어 취약점 (Errata / Bugs)",
                kpi_real_avail: "실질 가용 메모리",
                kpi_kernel_slab: "커널 슬랩 (Slab)",
                kpi_overcommit: "메모리 커밋",
                kpi_dirty_write: "디스크 쓰기 대기",
                mem_anon_title: "익명 메모리 (Anon - Active / Inactive)",
                mem_file_title: "파일 캐시 (File - Active / Inactive)",
                mem_kernel_title: "커널 관리 (PageTables / KernelStack)",
                mem_hugepages_title: "HugePages 구성",
                connections_title: "🔗 다른 서버 활성 네트워크 연결 (Active Connections)",
                filter_connections: "연결 검색...",
                th_conn_type: "구분",
                th_conn_local: "로컬 주소",
                th_conn_foreign: "원격 서버 주소 (Foreign)",
                th_conn_state: "연결 상태",
                conn_type_remote: "🌐 원격 서버",
                conn_type_local: "🔄 로컬 루프백",
                no_conns: "활성 네트워크 연결이 없습니다.",
                sysctl_title: "⚡ 핵심 커널 네트워크 & 메모리 튜닝 (sysctl)",
                anomaly_header: "🔍 커널 오류 & 비정상 이벤트 자동 스캐너",
                anomaly_desc: "OOM Killer, 세그멘테이션 폴트, 블록 디바이스 I/O 에러 감지 결과"
            }},
            en: {{
                theme_light: "Light Mode",
                theme_dark: "Dark Mode",
                lang_btn: "한국어",
                print_btn: "PDF / Print",
                system_status: "SYSTEM HEALTH STATUS",
                status_healthy: "HEALTHY",
                status_attention: "ATTENTION",
                status_critical: "CRITICAL",
                archive_lbl: "Archive:",
                uptime_lbl: "Uptime:",
                collected_lbl: "Collected:",
                sos_ver_lbl: "SOS Version:",
                kpi_cpu_cores: "CPU Cores & Load",
                kpi_load_avg: "Load Avg",
                kpi_mem_util: "Memory Utilization",
                kpi_mem_used: "Used",
                kpi_mem_avail: "Avail",
                kpi_buff_cache: "Buff/Cache",
                kpi_swap_util: "Swap Activity",
                kpi_swap_total: "Total",
                kpi_failed_svc: "Failed Services",
                kpi_systemd_status: "Systemd Service States",
                units_cnt: "Units",
                tab_overview: "📊 Diagnostics & Overview",
                tab_users: "👤 Users",
                tab_storage: "💾 Storage",
                tab_memory: "🧠 CPU & Memory",
                tab_services: "⚙️ Services & Boot",
                tab_network: "🌐 Network & Ports",
                tab_processes: "📈 Processes",
                tab_logs: "📜 Logs & Kernel",
                tab_raw: "🔍 Raw JSON",
                diag_assessment: "System Diagnostic Assessment",
                host_details: "Host & Environment Details",
                recent_logins: "Recent User Logins (wtmp)",
                users_title: "System Accounts & Sudo Privileges (getent passwd / sudoers.d)",
                local_disks_title: "💾 Local / Root OS Disk",
                additional_disks_title: "🗄️ Additional Disks (Attached Disks)",
                no_additional_disks: "None",
                no_additional_disks_sub: "No extra attached block storage volumes detected.",
                block_devices_title: "Block Devices (Local & Additional Disks - lsblk)",
                badge_local_disk: "Local / OS Disk",
                badge_extra_vol: "Extra Volume",
                partitions_layout: "Partition Layout:",
                disk_mount_role: "Role / Mount:",
                unmounted_data: "Unmounted / Data Volume",
                no_local_disk: "No Local Disk Detected",
                type_regular: "Regular User",
                type_system: "System Account",
                has_sudo_priv: "Admin Privileges Included",
                type_root: "Superuser (Root)",
                th_shell: "Login Shell",
                th_home: "Home Dir",
                th_procs: "Procs",
                th_last_login: "Last Login",
                th_type: "Account & Privilege",
                fs_mounts: "Filesystem Mounts & Disk Space (df -h)",
                cpu_specs: "CPU Hardware Specs (lscpu)",
                ram_dist: "RAM & Swap Memory Distribution",
                failed_units_title: "Failed Systemd Units",
                boot_blame_title: "Boot Time Contributors (systemd-analyze blame)",
                net_ifaces_title: "Network Interfaces",
                routes_title: "Routing Table Highlights",
                ports_title: "Active Listening Ports (netstat)",
                top_cpu_title: "Top CPU Consumers",
                top_mem_title: "Top Memory Consumers",
                all_procs_title: "Active Processes (Top Resource Usage)",
                dmesg_title: "Kernel Warnings & Critical Events (dmesg)",
                journal_title: "Systemd Boot Journal Warnings & Errors (journalctl)",
                raw_json_title: "Parsed Diagnostics JSON Payload",
                kv_hostname: "Hostname",
                kv_os: "Operating System",
                kv_kernel: "Kernel Release",
                kv_arch: "Architecture",
                kv_date: "Collection Timestamp",
                kv_uptime: "System Uptime",
                kv_aws_id: "AWS Instance ID",
                kv_aws_type: "AWS Instance Type",
                kv_aws_az: "Availability Zone (AZ)",
                kv_nginx: "Nginx Web Server",
                kv_cpu_model: "Processor Model",
                kv_cpu_cores: "Logical CPU Cores",
                kv_cpu_threads: "Threads per Core",
                kv_cpu_arch: "Architecture",
                kv_cpu_load: "Load Average (1m, 5m, 15m)",
                th_mount: "Mount Point",
                th_fs: "Filesystem / Device",
                th_size: "Total Size",
                th_used: "Used",
                th_avail: "Available",
                th_use_pct: "Usage %",
                th_user: "User",
                th_session: "TTY / Session",
                th_source_ip: "Source IP",
                th_login_time: "Login Time & Status",
                th_proto: "Protocol",
                th_port: "Port",
                th_binding: "Binding Address",
                th_prog: "Process / Program",
                th_stat: "Stat",
                th_pid: "PID",
                th_cmd: "Command",
                action_label: "Action:",
                ref_source: "Reference File:",
                filter_mounts: "Filter mounts...",
                filter_ports: "Filter ports...",
                filter_procs: "Filter processes...",
                filter_users: "Filter users...",
                checklist_title: "🛡️ Security & Ops Health Checklist",
                ssh_audit_title: "🔐 SSH Remote Access & Daemon Audit (sshd -T)",
                kv_ssh_port: "SSH Port",
                kv_pwd_auth: "Password Authentication",
                kv_pubkey_auth: "Public Key Authentication",
                kv_root_login: "Permit Root Login",
                kv_max_tries: "Max Auth Tries",
                kv_client_alive: "Session Keepalive Timeout",
                badge_enabled_warn: "⚠️ Enabled (Risk)",
                badge_disabled_safe: "✅ Disabled (Safe)",
                ssh_warn_advice: "⚠️ Security Advisory: Password authentication is enabled on this Bastion host. Enforcing key-based access (`PasswordAuthentication no`) in /etc/ssh/sshd_config is strongly recommended.",
                th_inodes: "Inodes Total",
                th_iuse: "Inode Usage %",
                timers_title: "⏰ Scheduled Timers (systemctl list-timers)",
                filter_timers: "Filter timers...",
                th_timer_unit: "Timer Unit (.timer)",
                th_timer_next: "Next Run Time",
                th_timer_left: "Time Left",
                th_timer_activates: "Triggers Service (Activates)",
                no_timers: "No active scheduled timers found.",
                crontab_title: "📅 Crontab & Scheduled Jobs",
                filter_crons: "Filter crons...",
                th_cron_user: "Type / User",
                th_cron_schedule: "Schedule",
                th_cron_cmd: "Command",
                th_cron_desc: "Description / Note",
                th_cron_source: "Source File",
                no_crons: "No scheduled crontab jobs found.",
                periodic_cron_title: "📁 Periodic Script Directories (/etc/cron.*)",
                none_text: "None",
                cpuinfo_title: "🔬 Kernel CPU Architecture & Hardware Analysis (/proc/cpuinfo)",
                meminfo_title: "🧪 Kernel Memory Allocation & VM Deep Analysis (/proc/meminfo)",
                kv_microcode: "Microcode",
                kv_l3_cache: "L3 Cache Size",
                kv_bogomips: "BogoMIPS / Address Sizes",
                kv_simd_ext: "SIMD / Vector Extensions",
                kv_crypto_sec: "Hardware Security & Crypto",
                kv_hw_bugs: "Hardware Vulnerabilities & Errata",
                kpi_real_avail: "Real Available Memory",
                kpi_kernel_slab: "Kernel Slab Cache",
                kpi_overcommit: "Committed Memory",
                kpi_dirty_write: "Pending Disk Write (Dirty)",
                mem_anon_title: "Anonymous Memory (Active / Inactive)",
                mem_file_title: "File Cache (Active / Inactive)",
                mem_kernel_title: "Kernel Overhead (PageTables / KernelStack)",
                mem_hugepages_title: "HugePages Configuration",
                connections_title: "🔗 Active Network Connections to Remote Servers",
                filter_connections: "Filter connections...",
                th_conn_type: "Type",
                th_conn_local: "Local Address",
                th_conn_foreign: "Remote Address (Foreign)",
                th_conn_state: "State",
                conn_type_remote: "🌐 Remote Server",
                conn_type_local: "🔄 Local Loopback",
                no_conns: "No active network connections found.",
                sysctl_title: "⚡ Core Kernel Network & Memory Tuning (sysctl)",
                anomaly_header: "🔍 Kernel Anomaly & Error Auto-Scanner",
                anomaly_desc: "Automated scan for OOM Killer invocations, segmentation faults, and disk I/O errors"
            }}
        }};

        let currentLang = localStorage.getItem('sos_report_lang') || 'ko';
        let currentTheme = localStorage.getItem('sos_report_theme') || 'dark';

        function applyTheme(theme) {{
            currentTheme = theme;
            localStorage.setItem('sos_report_theme', theme);
            const icon = document.getElementById('themeIcon');
            const label = document.getElementById('themeLabel');
            if (theme === 'light') {{
                document.body.classList.add('light-mode');
                if (icon) icon.textContent = '🌙';
                if (label) label.textContent = (currentLang === 'ko') ? '다크 모드' : 'Dark Mode';
            }} else {{
                document.body.classList.remove('light-mode');
                if (icon) icon.textContent = '☀️';
                if (label) label.textContent = (currentLang === 'ko') ? '라이트 모드' : 'Light Mode';
            }}
        }}

        function toggleTheme() {{
            applyTheme(currentTheme === 'dark' ? 'light' : 'dark');
        }}

        function applyLanguage(lang) {{
            currentLang = lang;
            localStorage.setItem('sos_report_lang', lang);

            // Update static elements with data-i18n
            document.querySelectorAll('[data-i18n]').forEach(el => {{
                const key = el.getAttribute('data-i18n');
                if (i18n[lang] && i18n[lang][key]) {{
                    el.textContent = i18n[lang][key];
                }}
            }});

            // Update dynamic bilingual text elements
            document.querySelectorAll('.i18n-elem').forEach(el => {{
                const text = el.getAttribute('data-' + lang);
                if (text) {{
                    el.textContent = text;
                }}
            }});

            // Update input placeholders
            document.querySelectorAll('.search-box').forEach(el => {{
                const key = el.getAttribute('data-i18n-placeholder');
                if (key && i18n[lang] && i18n[lang][key]) {{
                    el.placeholder = i18n[lang][key];
                }}
            }});

            // Update language toggle button text & icon
            const langLabel = document.getElementById('langLabel');
            const langIcon = document.getElementById('langIcon');
            if (lang === 'ko') {{
                if (langLabel) langLabel.textContent = 'English';
                if (langIcon) langIcon.textContent = '🌐';
            }} else {{
                if (langLabel) langLabel.textContent = '한국어';
                if (langIcon) langIcon.textContent = '🇰🇷';
            }}

            // Update theme button text according to new language
            const themeLabel = document.getElementById('themeLabel');
            if (themeLabel) {{
                if (currentTheme === 'light') {{
                    themeLabel.textContent = (lang === 'ko') ? '다크 모드' : 'Dark Mode';
                }} else {{
                    themeLabel.textContent = (lang === 'ko') ? '라이트 모드' : 'Light Mode';
                }}
            }}
        }}

        function toggleLang() {{
            applyLanguage(currentLang === 'ko' ? 'en' : 'ko');
        }}

        function switchTab(tabId, btn) {{
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btn.classList.add('active');
        }}

        function filterTable(input, tableId) {{
            const filter = input.value.toLowerCase();
            const table = document.getElementById(tableId);
            const tr = table.getElementsByTagName('tr');
            for (let i = 1; i < tr.length; i++) {{
                const text = tr[i].textContent || tr[i].innerText;
                tr[i].style.display = text.toLowerCase().indexOf(filter) > -1 ? '' : 'none';
            }}
        }}

        // Initialize state on DOM ready
        document.addEventListener('DOMContentLoaded', () => {{
            applyTheme(currentTheme);
            applyLanguage(currentLang);
        }});
    </script>
</body>
</html>
"""
        return html_template


def main():
    parser = argparse.ArgumentParser(
        description="Analyze sosreport archive (.tar.xz) and output an interactive HTML diagnostic report.",
        usage="python3 sosreport.py sourcefile outputfile"
    )
    parser.add_argument("sourcefile", help="Path to source sosreport archive (.tar.xz, .tar.gz, .tar)")
    parser.add_argument("outputfile", help="Path to output HTML file (or output directory)")

    parsed_args = parser.parse_args()

    # Validate source file
    input_path = Path(parsed_args.sourcefile).resolve()
    if not input_path.exists():
        print(f"[-] Error: Source file not found: {parsed_args.sourcefile}")
        sys.exit(1)

    # Resolve output path
    base_name = input_path.name
    for ext in [".tar.xz", ".tar.gz", ".tar.bz2", ".tar", ".txz"]:
        if base_name.endswith(ext):
            base_name = base_name[:-len(ext)]
            break

    out = Path(parsed_args.outputfile)
    if out.is_dir() or str(parsed_args.outputfile).endswith(("/", "\\")):
        out.mkdir(parents=True, exist_ok=True)
        output_file = out / f"{base_name}_report.html"
    elif out.suffix.lower() in [".html", ".htm"]:
        out.parent.mkdir(parents=True, exist_ok=True)
        output_file = out
    else:
        if out.exists() and out.is_dir():
            output_file = out / f"{base_name}_report.html"
        elif "." not in out.name:
            out.mkdir(parents=True, exist_ok=True)
            output_file = out / f"{base_name}_report.html"
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            output_file = out

    output_file = output_file.resolve()

    # Parse and generate report
    try:
        parser_inst = SOSReportParser(input_path)
        parser_inst.extract_needed_files()
        parser_inst.parse_all()

        generator = HTMLReportGenerator(parser_inst.data)
        html_content = generator.generate()

        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        print("\n" + "=" * 60)
        print("🎉 SOSReport Analysis Completed Successfully!")
        print(f"📌 Input Archive : {input_path}")
        print(f"📊 Target Host   : {parser_inst.data['system'].get('hostname')}")
        print(f"🩺 Health Score  : {parser_inst.data['health_score']}/100")
        print(f"📄 Output Report : {output_file}")
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"[-] Error generating report: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
