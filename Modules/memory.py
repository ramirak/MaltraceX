import os

## Windows only
if os.name == 'nt':
    import wmi

    def collect_processes(duration):
        duration = int(duration)
        processes = {}
        c = wmi.WMI()
        process_watcher = c.Win32_Process.watch_for("creation")
        try:
            while True:
                new_process = process_watcher(timeout_ms=duration*1000)          
                processes.update({ new_process.ExecutablePath: new_process.Caption})
        except wmi.x_wmi_timed_out:
            print("Process watcher stopped.")
        except Exception as e:
            print(e)
            return False
        return processes

else:
    def take_memory_snapshot():
        return {}
