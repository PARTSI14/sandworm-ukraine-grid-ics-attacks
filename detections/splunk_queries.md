# Splunk queries (auto-generated from the Sigma rules)

Converted with pySigma + pysigma-backend-splunk (no field-mapping pipeline). Add your own `index=` / `sourcetype=` prefix and map the fields to your data: Sysmon or Windows 4688 (`Image`, `CommandLine`, `ParentImage`), Sysmon Event 11 (`TargetFilename`), Linux auditd, Zeek `conn.log` (`id.orig_h`, `id.resp_p`).

## Windows - CaddyWiper Deployment Pattern: Executable Started From C:\Windows Root by a Scheduled Task

Source: `sigma/caddywiper_gpo_scheduled_task_payload.yml`

```spl
(ParentImage IN ("*\\svchost.exe", "*\\taskeng.exe")) ParentCommandLine="*Schedule*" NOT (Image IN ("*\\explorer.exe", "*\\regedit.exe", "*\\notepad.exe", "*\\hh.exe", "*\\write.exe", "*\\splwow64.exe", "*\\winhlp32.exe", "*\\bfsvc.exe", "*\\HelpPane.exe"))
| regex Image="(?i)^C:\\\\Windows\\\\[^\\\\]+\\.exe$"
```

## Active Directory - Group Policy Scheduled Task (ScheduledTasks.xml) Created or Modified in SYSVOL

Source: `sigma/gpo_scheduled_task_xml_written.yml`

```spl
TargetFilename="*\\SYSVOL\\*" TargetFilename="*\\ScheduledTasks\\ScheduledTasks.xml"
```

## Windows - Industroyer2 and ARGUEPATCH File Names Executed (IOC)

Source: `sigma/industroyer2_arguepatch_ioc.yml`

```spl
Image IN ("*\\108_100.exe", "*\\zrada.exe")
```

## Windows OT Host - Executable Renamed With .MZ Extension (Industroyer2 behaviour)

Source: `sigma/industroyer2_process_renamed_mz.yml`

```spl
TargetFilename="*.exe.MZ"
```

## Linux / Solaris - Whole-Disk Shred, dd From /dev/random or Forced SysRq Reboot

Source: `sigma/linux_disk_wipe_or_sysrq_reboot.yml`

```spl
(Image="*/shred" (CommandLine IN ("*/dev/sd*", "*/dev/nvme*", "*/dev/vd*", "*/dev/dsk/*"))) OR (Image="*/dd" CommandLine="*if=/dev/random*" CommandLine="*of=/dev/*") OR CommandLine="*sysrq-trigger*"
```

## MicroSCADA - scilc.exe Executes an External SCIL Program (-do)

Source: `sigma/microscada_scilc_do_execution.yml`

```spl
Image="*\\scilc.exe" CommandLine="*-do*"
```

## Windows - Script From a Non-System Drive Launches a Hidden Batch File (ISO / CD-ROM autorun chain)

Source: `sigma/vbs_from_removable_or_iso_drive_runs_batch.yml`

```spl
(ParentImage IN ("*\\wscript.exe", "*\\cscript.exe")) Image="*\\cmd.exe" CommandLine="*.bat*"
| regex ParentCommandLine="(?i)[d-z]:\\\\[^ ]*\\.vbs"
```

## OT Network - IEC 60870-5-104 Traffic From a Host Outside the SCADA Allow-List

Source: `sigma/zeek_iec104_from_unexpected_host.yml`

```spl
id.resp_p=2404 NOT (id.orig_h IN ("10.0.0.10", "10.0.0.11"))
```

## Network - SSH Attempts on Unusual Ports Used by ORCSHRED (2468, 24687, 522)

Source: `sigma/zeek_ssh_unusual_ports_orcshred.yml`

```spl
id.resp_p IN (2468, 24687, 522)
```
