import tkinter as tk
import subprocess
from tkinter import messagebox
import webbrowser

# Global variables to store the subprocess object and file object
process = None
file_handle = None

def start_script():
    global process, file_handle
    # Path to the Python script to run
    script_path = r"C:\Users\vagmi\Documents\Quantum ARP SPOOF DETECTION\main.py"

    # Open the command prompt and run the Python script
    process = subprocess.Popen(["python", script_path], shell=True)
    
def stop_program():
    if messagebox.askokcancel("Quit", "Do you want to quit the program?"):
        root.destroy()

def open_logs():
    webbrowser.open(r"C:\Users\vagmi\Documents\Quantum ARP SPOOF DETECTION\arp_spoof_log.xlsx")

def open_graph():
    script_path = r"C:\Users\vagmi\Documents\Quantum ARP SPOOF DETECTION\graph.py"
    # Add code here to open and execute the graph script
    try:
        with open(script_path, 'r') as script_file:
            script_code = script_file.read()
            exec(script_code)
    except FileNotFoundError:
        messagebox.showerror("Error", f"File '{script_path}' not found.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Create the GUI window
root = tk.Tk()
root.title("ARP Spoof Detector")

# Configure the window size to 3x4 grid
root.geometry("400x300")

# Create a frame to hold the widgets
frame = tk.Frame(root, bg="lightgray", padx=50, pady=50)
frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

# Label to display the name of the application
app_name_label = tk.Label(frame, text="Quantum ARP Guard", font=("Helvetica", 16), bg="lightgray")
app_name_label.grid(row=0, column=0, columnspan=2, pady=20)

# Button to start the script
start_button = tk.Button(frame, text="Start", command=start_script, bg="green", fg="white", padx=20, pady=10)
start_button.grid(row=1, column=0, pady=10)

# Button to stop the script
stop_button = tk.Button(frame, text="Stop", command=stop_program, bg="red", fg="white", padx=20, pady=10)
stop_button.grid(row=1, column=1, pady=10)

# Hyperlink for logs
logs_label = tk.Label(frame, text="Logs", fg="blue", cursor="hand2")
logs_label.grid(row=2, column=0, pady=5)
logs_label.bind("<Button-1>", lambda e: open_logs())

# Hyperlink for graph
graph_label = tk.Label(frame, text="Graph", fg="blue", cursor="hand2")
graph_label.grid(row=2, column=1, pady=5)
graph_label.bind("<Button-1>", lambda e: open_graph())

# Run the GUI application
root.mainloop()
