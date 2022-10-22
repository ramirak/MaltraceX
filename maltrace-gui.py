import threading
import tkinter as tk
from tkinter import BOTTOM, LEFT, TOP, Entry, Text, messagebox, filedialog, Frame
from threading import *
from ctypes import windll
import os, sys, whois
from tkinter import ttk
from Analysis.integrity import check_integrity, take_snapshot
from Analysis.memory import get_connections, get_processes
from Analysis.pestruct import write_pe_report
from Api.vt import write_vt_report
import Data.enums as enums
import Data.files as files
from threading import Lock


windll.shcore.SetProcessDpiAwareness(1)

main_color = "#000000"
secondary_color = "#0F0F0F"
hover_color = "#25272A"
font_color = "#F34D60"
font_secondary_color = "#F34D60"
font_family = "Segoe UI Semilight"
icon = "Imgs/icon.ico"

progress_bar = None
critical_function_lock = Lock()
owner_id = 0


def reload_program():
    res = messagebox.askquestion("Alert", "Reload program? This will stop any running operations.")
    if res == "yes":
        python = sys.executable
        os.execl(python, python, * sys.argv)


def get_ownership():
    global owner_id
    if not critical_function_lock.locked():
        critical_function_lock.acquire()
        owner_id = threading.get_ident()
        return 1
    return 0


def thread_worker(func, args):
    global in_progress
    res = None
    
    # Try getting ownership for progress bar
    if progress_bar != None and get_ownership():
        progress_bar.start()

    if len(args) > 0:
        res = func(*args)
    else:
        res = func()
    
    if progress_bar != None and threading.get_ident() == owner_id:
        progress_bar.stop()
        critical_function_lock.release()
    assert_res(res)


def assert_res(res):    
    if res == enums.results.SUCCESS.value:
        messagebox.showinfo("information", "Operation completed successfully")
    elif res == enums.results.FINISHED_WITH_ERRORS.value:
        messagebox.showinfo("information", "Operation completed with errors.")
    elif res == enums.results.ALREADY_RUNNING.value:
        messagebox.showinfo("information", "Operation is already in progress.")
    elif res == enums.results.SNAPSHOT_NOT_FOUND.value:
        messagebox.showinfo("information", "Snapshot not found!")
    elif res == enums.results.API_KEY_NOT_FOUND.value:
        messagebox.showinfo("information", "Please set your API key first.")
    elif res == enums.results.NO_MATCH_FOUND.value:
        messagebox.showinfo("information", "No match was found.")
    elif res == enums.results.NON_PE_FILE.value:
        messagebox.showinfo("information", "Non PE file.")
    elif res == enums.results.GENERAL_FAILURE.value:
        messagebox.showinfo("information", "Operation failed.")
    else:
        messagebox.showinfo("information", "Unknown error")
      

def open_text_file(path):
    if os.path.isfile(path):
        osCommandString = "notepad.exe %s" % path
        os.system(osCommandString)


def center(win):
    win.update_idletasks()
    width = win.winfo_width()
    frm_width = win.winfo_rootx() - win.winfo_x()
    win_width = width + 2 * frm_width
    height = win.winfo_height()
    titlebar_height = win.winfo_rooty() - win.winfo_y()
    win_height = height + titlebar_height + frm_width
    x = win.winfo_screenwidth() // 2 - win_width // 2
    y = win.winfo_screenheight() // 2 - win_height // 2
    win.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    win.deiconify()


def create_progress_bar(window):
    s = ttk.Style()
    s.theme_use('clam')
    s.configure("red.Horizontal.TProgressbar", foreground=font_color, background="white", troughcolor=main_color)

    # progressbar
    progress_bar = ttk.Progressbar(
        window,
        orient='horizontal',
        mode='indeterminate',
        length=280,
        style="red.Horizontal.TProgressbar"
    )
    progress_bar.pack()
    return progress_bar

    
def ask_user(title, msg, params):
    res = messagebox.askquestion(title, msg)
    if res == "yes":
        if params != None:
            Thread(target = thread_worker, args=(params), daemon=True).start()
        else:
            Thread(target = thread_worker, daemon=True).start()


def ask_user_input(header):
    window = tk.Toplevel()
    window.configure(bg=main_color)
    window.minsize(width=400, height=10)
    window.iconbitmap(icon)
    center(window)
    args = {"width":25, "border":0, "bg":secondary_color, "fg":font_color, "font":("Serif", 11) }

    tk.Label(window, text=header, **args).pack(pady=5)
    entry= Entry(window, **args)
    entry.focus_set()
    entry.pack(pady=20, padx=10)
    tk.Button(window, text= "Run", **args, command=lambda: show_output_window(whois.whois, [entry.get()])).pack(pady=5)
    tk.Button(window, text= "Close", **args, command=lambda:window.destroy()).pack(pady=5)


def browseFiles(func , args):
    filename = filedialog.askopenfilename(initialdir = "/", title = "Select a File")
    args.insert(0, filename)
    if len(filename) <= 1:
        return
    res = messagebox.askquestion("Warning", "A scan will be initiated for %s\nContinue?\n" % filename)
    if res == "yes":
        thread = Thread(target = thread_worker, args=(func, args,), daemon=True)
        thread.start()
   

def show_output_window(func ,args):
    window = tk.Toplevel()
    window.configure(bg=main_color)
    window.minsize(width=1500, height=750)
    window.iconbitmap(icon)
    center(window)
    
    T = Text(window, height=30, width= 150, bg=secondary_color, fg=font_color)
    T.pack(side=TOP)
    res = ""

    def do():
        T.delete('1.0',tk.END)
        res = func(*args)
        T.insert(tk.END,res)

    do()

    button_args = {"height":2, "width":25, "border":0, "bg":secondary_color, "fg":font_color, "font":("Serif", 10) }
    tk.Button(window, text="Close", **button_args, command=lambda: window.destroy()).pack(pady=5,side=BOTTOM)
    tk.Button(window, text="Refresh", **button_args, command= lambda: do()).pack(pady=5,side=BOTTOM)


def show_log_window():
    window = tk.Toplevel()
    window.configure(bg=main_color)
    window.iconbitmap(icon)
    window.minsize(width=400, height=400)
    window.title("MaltraceX")
    center(window)
    header = tk.Label(window, text="MaltraceX Logs", bg=main_color, fg=font_secondary_color, font=(font_family, 15, "bold", "italic"))
    header.bind('<Enter>', lambda e: e.widget.config(fg="white"))
    header.bind('<Leave>', lambda e: e.widget.config(fg=font_secondary_color))
    header.pack(pady=10)
    button_args = {"height":3, "width":25, "border":0, "bg":secondary_color, "fg":font_color, "font":("Serif", 10) }
    
    def do(path):
        show_output_window(files.show_file_content ,[path])


    buttons = [tk.Button(window, text="Traces", **button_args, command=lambda: do(enums.files.TRACES.value)),
                tk.Button(window, text="Virus total", **button_args, command=lambda: do(enums.files.REPORT.value)),
                tk.Button(window, text="PE report", **button_args, command=lambda: do(enums.files.PESCAN.value)),
                tk.Button(window, text="Close", **button_args, command=lambda: window.destroy())]

    for b in buttons:
        b.bind('<Enter>', lambda e: e.widget.config(bg=hover_color))
        b.bind('<Leave>', lambda e: e.widget.config(bg=secondary_color))
        b.pack(pady=5, side=TOP)


def create_main_window():
    window = tk.Tk()
    window.configure(bg=main_color)
    window.iconbitmap(icon)
    window.minsize(width=800, height=500)
    window.title("MaltraceX")
    center(window)
    return window


def create_buttons(root):
    frames = []
    conf = files.retrieve_from_file(enums.files.CONFIG.value)
    virus_total_scan, virus_total_key = bool(conf["virus_total_scan"]), conf["virus_total_key"]
    snapshot_path = conf["snapshot_path"]

    for i in range(4):
        frames.append(Frame(root, bg=main_color))
        frames[i].pack()

    button_args = {"height":3, "width":25, "border":0, "bg":secondary_color, "fg":font_color, "font":("Serif", 10) }

    buttons = [tk.Button(frames[0],text="Take snapshot", **button_args,
                        command=lambda:ask_user("MaltraceX","This will create a snapshot for %s\nContinue?" % snapshot_path, [take_snapshot, [snapshot_path]])),

                tk.Button(frames[0],text="Check system integrity", **button_args,
                        command=lambda:ask_user("MaltraceX","This will check the integrity of %s\nContinue?" % snapshot_path, [check_integrity, [snapshot_path, virus_total_scan]])),

                tk.Button(frames[0],text="Show running processes", **button_args,
                        command=lambda: show_output_window(get_processes, [])),

                tk.Button(frames[1],text="Show network connections", **button_args,
                        command=lambda: show_output_window(get_connections, [])),

                tk.Button(frames[1],text="Analyze PE struct", **button_args,
                        command=lambda: browseFiles(write_pe_report, [])),

                tk.Button(frames[1],text="Virus-Total Scan", **button_args,
                        command=lambda: browseFiles(write_vt_report, [])),

                tk.Button(frames[2],text="Whois lookup", **button_args,
                        command=lambda: ask_user_input("Whois Lookup")),

                tk.Button(frames[2],text="Show logs", **button_args,
                        command=lambda: show_log_window()),

                tk.Button(frames[3],text="Exit", **button_args, 
                        command = lambda: exit(0) if messagebox.askquestion("MaltraceX", "Are you sure you want to exit?") == "yes" else None),

                tk.Button(frames[2],text="Settings", **button_args,
                        command=lambda: [open_text_file(enums.files.CONFIG.value), reload_program()])]

    for b in buttons:
        b.bind('<Enter>', lambda e: e.widget.config(bg=hover_color))
        b.bind('<Leave>', lambda e: e.widget.config(bg=secondary_color))
        b.pack(padx=10, pady=20, side=LEFT)


root = create_main_window()
header = tk.Label(text="MaltraceX", bg=main_color, fg=font_secondary_color, font=(font_family, 18, "bold", "italic"))
header.bind('<Enter>', lambda e: e.widget.config(fg="white"))
header.bind('<Leave>', lambda e: e.widget.config(fg=font_secondary_color))
header.pack(pady=10)
progress_bar = create_progress_bar(root)
create_buttons(root)
root.mainloop()
