import sys
import customtkinter as ctk
import ctypes
from ctypes import wintypes, windll, create_string_buffer, c_size_t, Structure
from ctypes.wintypes import DWORD
from dataclasses import dataclass
import tkinter as tk
import os
import pygame
import requests
from typing import List
import threading
import struct


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_as_admin():
    script = sys.argv[0]
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, script, None, 1
    )


if not is_admin():
    run_as_admin()
    sys.exit()

# Memory access constants
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READONLY = 0x02
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000


@dataclass
class Window:
    hwnd: int
    title: str
    process_id: int


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_size_t),
        ("AllocationBase", c_size_t),
        ("AllocationProtect", DWORD),
        ("RegionSize", c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]


class MemoryMagic:
    def __init__(self):
        self.buffer_size = 1024 * 1024 * 20
        self.value_type = "i"
        self.value_size = struct.calcsize(self.value_type)
        self.found_addresses = []
        self.thread_count = 20

    def get_all_windows(self) -> List[Window]:
        windows = []

        def enum_windows_callback(hwnd, _):
            if windll.user32.IsWindowVisible(hwnd):
                length = windll.user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    title = create_string_buffer(length + 1)
                    windll.user32.GetWindowTextA(hwnd, title, length + 1)
                    process_id = DWORD()
                    windll.user32.GetWindowThreadProcessId(
                        hwnd, ctypes.byref(process_id)
                    )
                    windows.append(
                        Window(hwnd, title.value.decode(), process_id.value)
                    )
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
        )
        windll.user32.EnumWindows(WNDENUMPROC(enum_windows_callback), 0)
        return windows

    def _scan_region(self, handle, start_addr, size, desired_bytes, addresses):
        try:
            buffer = (ctypes.c_char * size)()
            bytes_read = c_size_t(0)

            if windll.kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(start_addr),
                buffer,
                size,
                ctypes.byref(bytes_read),
            ):
                buffer_data = bytes(buffer)[: bytes_read.value]
                offset = 0
                while True:
                    offset = buffer_data.find(desired_bytes, offset)
                    if offset == -1:
                        break
                    addresses.append(start_addr + offset)
                    offset += self.value_size
        except Exception:
            pass

    def _scan_worker(self, handle, regions, desired_bytes, addresses):
        for region in regions:
            self._scan_region(
                handle, region[0], region[1], desired_bytes, addresses
            )

    def memory_search(
        self, process_id: int, desired_value: int, search_addresses=None
    ) -> List[int]:
        handle = windll.kernel32.OpenProcess(
            PROCESS_VM_READ
            | PROCESS_VM_WRITE
            | PROCESS_VM_OPERATION
            | PROCESS_QUERY_INFORMATION,
            False,
            process_id & 0xFFFFFFFF,
        )

        if not handle:
            return []

        if search_addresses:
            return self._search_specific_addresses(
                handle, search_addresses, desired_value
            )

        regions_to_scan = self._get_regions_to_scan(handle)
        desired_bytes = struct.pack(self.value_type, desired_value)
        thread_regions = [[] for _ in range(self.thread_count)]

        for i, region in enumerate(regions_to_scan):
            thread_regions[i % self.thread_count].append(region)

        addresses = self._run_scan_threads(
            handle, thread_regions, desired_bytes
        )
        windll.kernel32.CloseHandle(handle)
        return sorted(addresses)

    def _search_specific_addresses(self, handle, addresses, desired_value):
        results = []
        for addr in addresses:
            buffer = (ctypes.c_char * self.value_size)()
            bytes_read = c_size_t(0)
            if windll.kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(addr),
                buffer,
                self.value_size,
                ctypes.byref(bytes_read),
            ):
                value = struct.unpack(self.value_type, buffer)[0]
                if value == desired_value:
                    results.append(addr)
        return results

    def _get_regions_to_scan(self, handle):
        regions = []
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()

        while ctypes.windll.kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        ):
            if (
                mbi.State & MEM_COMMIT
                and mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)
                and mbi.RegionSize > 0
            ):
                for offset in range(0, mbi.RegionSize, self.buffer_size):
                    chunk_size = min(self.buffer_size, mbi.RegionSize - offset)
                    regions.append((mbi.BaseAddress + offset, chunk_size))
            address = mbi.BaseAddress + mbi.RegionSize
        return regions

    def _run_scan_threads(self, handle, thread_regions, desired_bytes):
        threads = []
        thread_results = [[] for _ in range(self.thread_count)]

        for i in range(self.thread_count):
            thread = threading.Thread(
                target=self._scan_worker,
                args=(
                    handle,
                    thread_regions[i],
                    desired_bytes,
                    thread_results[i],
                ),
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        addresses = []
        for thread_result in thread_results:
            addresses.extend(thread_result)
        return addresses

    def write_address_value(
        self, process_id: int, address: int, value: int
    ) -> str:
        handle = windll.kernel32.OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            False,
            process_id & 0xFFFFFFFF,
        )

        if not handle:
            return f"Failed to open process {process_id}"

        try:
            buffer = struct.pack(self.value_type, value)
            bytes_written = c_size_t()

            if windll.kernel32.WriteProcessMemory(
                handle,
                ctypes.c_void_p(address),
                buffer,
                len(buffer),
                ctypes.byref(bytes_written),
            ):
                return f"Success"
            return f"Failed to write to address 0x{address:X}"
        except Exception as e:
            return f"Error writing to memory: {e}"
        finally:
            windll.kernel32.CloseHandle(handle)


class App(ctk.CTk):
    def __init__(self, magic):
        super().__init__()
        self.magic = magic
        self.windows = []
        self.found_addresses = []
        self.setup_window()
        self.create_widgets()
        self.populate_windows()
        self.sound_file = "0114.mp3"
        pygame.mixer.init()

    def setup_window(self):
        self.title("Memory Magic")
        self.geometry("600x245")
        ctk.set_appearance_mode("dark")
        self.black = "#000000"
        self.red = "#89CFF0"
        self.white = "#FFFFFF"

        self.main_frame = ctk.CTkFrame(self, fg_color=self.black)
        self.main_frame.pack(fill="both", expand=True, padx=0, pady=0)

        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)

        self.attributes("-topmost", True)
        self.lift()

    def create_widgets(self):
        self.create_search_frame()
        self.create_results_frame()
        self.create_modification_frame()

    def refresh_windows(self):
        self.windows = self.magic.get_all_windows()
        self.window_list.configure(
            values=[
                f"{win.title} - PID: {win.process_id}" for win in self.windows
            ]
        )
        self.address_list.insert("1.0", "Window list refreshed.\n")
        self.update()

    def create_search_frame(self):
        search_frame = ctk.CTkFrame(self.main_frame, fg_color=self.black)
        search_frame.grid(
            row=0, column=0, columnspan=2, sticky="ew", pady=(0, 5)
        )
        search_frame.grid_columnconfigure(0, weight=1)
        search_frame.grid_columnconfigure(1, weight=1)

        self.window_list = ctk.CTkComboBox(
            search_frame,
            width=280,
            fg_color=self.black,
            button_color=self.red,
            text_color=self.white,
            border_color=self.red,
        )
        self.window_list.set("Select a Window")
        self.window_list.grid(
            row=0, column=0, padx=(0, 5), pady=5, sticky="ew"
        )

        self.search_value_entry = ctk.CTkEntry(
            search_frame,
            width=280,
            placeholder_text="Value to Search",
            fg_color=self.black,
            text_color=self.white,
            border_color=self.red,
        )
        self.search_value_entry.grid(
            row=0, column=1, padx=(5, 0), pady=5, sticky="ew"
        )

        self.value_type_list = ctk.CTkComboBox(
            search_frame,
            width=280,
            fg_color=self.black,
            button_color=self.red,
            text_color=self.white,
            border_color=self.red,
        )
        self.value_type_list.set("Select Value Type")
        self.value_type_list.configure(
            values=[
                "4-byte Integer",
                "4-byte Float",
                "8-byte Double",
                "2-byte Integer",
            ]
        )
        self.value_type_list.grid(
            row=1, column=0, padx=(0, 5), pady=5, sticky="ew"
        )

        self.refresh_button = ctk.CTkButton(
            search_frame,
            text="Refresh Windows",
            command=self.refresh_windows,
            fg_color=self.red,
            text_color=self.white,
            width=120,
        )
        self.refresh_button.grid(
            row=1, column=1, padx=(5, 0), pady=5, sticky="ew"
        )

    def refresh_windows(self):
        self.windows = self.magic.get_all_windows()
        self.window_list.configure(
            values=[
                f"{win.title} - PID: {win.process_id}" for win in self.windows
            ]
        )
        self.address_list.insert("1.0", "Window list refreshed.\n")
        self.update()

    def create_results_frame(self):
        results_frame = ctk.CTkFrame(self.main_frame, fg_color=self.black)
        results_frame.grid(
            row=1, column=0, columnspan=2, sticky="nsew", pady=5
        )
        results_frame.grid_columnconfigure(0, weight=1)
        button_frame = ctk.CTkFrame(results_frame, fg_color=self.black)
        button_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))

        self.search_button = ctk.CTkButton(
            button_frame,
            text="First Scan",
            command=self.search_memory,
            fg_color=self.red,
            text_color=self.white,
            width=120,
        )
        self.search_button.pack(side="left", padx=5)

        self.next_scan_button = ctk.CTkButton(
            button_frame,
            text="Next Scan",
            command=self.next_scan,
            fg_color=self.red,
            text_color=self.white,
            width=120,
        )
        self.next_scan_button.pack(side="left", padx=5)
        self.address_list = ctk.CTkTextbox(
            results_frame,
            width=580,
            height=80,
            fg_color=self.black,
            text_color=self.white,
            border_color=self.red,
        )
        self.address_list.grid(row=1, column=0, sticky="nsew", pady=(0, 5))

    def create_modification_frame(self):
        bottom_frame = ctk.CTkFrame(self.main_frame, fg_color=self.black)
        bottom_frame.grid(
            row=2, column=0, columnspan=2, sticky="ew", pady=(5, 0)
        )
        bottom_frame.grid_columnconfigure(0, weight=1)
        self.modify_frame = ctk.CTkFrame(bottom_frame, fg_color=self.black)
        self.modify_frame.grid(row=0, column=0, padx=5)
        self.modify_address_entry = ctk.CTkEntry(
            self.modify_frame,
            placeholder_text="Address (hex)",
            fg_color=self.black,
            text_color=self.white,
            border_color=self.red,
            width=180,
        )
        self.modify_address_entry.pack(side="left", padx=5)
        self.modify_value_entry = ctk.CTkEntry(
            self.modify_frame,
            placeholder_text="New Value",
            fg_color=self.black,
            text_color=self.white,
            border_color=self.red,
            width=180,
        )
        self.modify_value_entry.pack(side="left", padx=5)
        self.modify_button = ctk.CTkButton(
            self.modify_frame,
            text="Modify",
            command=self.modify_value,
            fg_color=self.red,
            text_color=self.white,
            width=85,
        )
        self.modify_button.pack(side="left", padx=5)
        self.modify_frame.grid_remove()
        self.custom_button = ctk.CTkButton(
            bottom_frame,
            text="Custom",
            command=self.toggle_modify,
            fg_color=self.red,
            text_color=self.white,
            width=85,
        )
        self.custom_button.grid(row=0, column=1, padx=5)

    def toggle_modify(self):
        if self.modify_frame.winfo_ismapped():

            self.modify_frame.grid_remove()
            self.custom_button.configure(text="Custom")
        else:
            self.modify_frame.grid()
            self.custom_button.configure(text="Hide Custom")

    def populate_windows(self):
        self.windows = self.magic.get_all_windows()
        self.window_list.configure(
            values=[
                f"{win.title} - PID: {win.process_id}" for win in self.windows
            ]
        )

    def get_selected_window(self):
        selected_value = self.window_list.get()
        if not selected_value or selected_value == "Select a Window":
            self.address_list.insert("1.0", "Please select a window.\n")
            return None

        selected_index = next(
            (
                i
                for i, win in enumerate(self.windows)
                if f"{win.title} - PID: {win.process_id}" == selected_value
            ),
            None,
        )

        if selected_index is None:
            self.address_list.insert("1.0", "Invalid selection.\n")
            return None

        return self.windows[selected_index]

    def download_sound(self, url):
        try:
            if not os.path.exists(self.sound_file):
                print(f"Downloading sound file to {self.sound_file}...")
                response = requests.get(url, stream=True)
                response.raise_for_status()
                with open(self.sound_file, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                print("Download complete.")
            else:
                print(f"done")
        except Exception as e:
            print(f"Error downloading sound file: {e}")

    def play_sound(self):
        try:
            pygame.mixer.music.load(self.sound_file)
            pygame.mixer.music.play()
            while pygame.mixer.music.get_busy():
                continue
        except Exception as e:
            print(f"Error playing sound: {e}")

    def search_memory(self):
        try:
            selected_window = self.get_selected_window()
            if not selected_window:
                return

            value = int(self.search_value_entry.get())
            selected_value_type = self.value_type_list.get()

            if selected_value_type == "4-byte Float":
                self.magic.value_type = "f"  # 4-byte float
                self.magic.value_size = struct.calcsize(self.magic.value_type)
            elif selected_value_type == "8-byte Double":
                self.magic.value_type = "d"  # 8-byte double
                self.magic.value_size = struct.calcsize(self.magic.value_type)
            else:
                self.magic.value_type = "i"  # Default to 4-byte integer
                self.magic.value_size = struct.calcsize(self.magic.value_type)

            self.address_list.delete("1.0", "end")
            self.address_list.insert("1.0", "Scanning memory... Please wait\n")
            self.update()

            self.found_addresses = self.magic.memory_search(
                selected_window.process_id, value
            )
            self.update_address_list()
            self.download_sound(
                "https://github.com/prototbh/TEMP/raw/refs/heads/main/0114.MP3"
            )
            self.play_sound()

        except Exception as e:
            self.address_list.insert("1.0", f"Error: {e}\n")

    def next_scan(self):
        try:
            selected_window = self.get_selected_window()
            if not selected_window:
                return

            value = int(self.search_value_entry.get())
            self.address_list.delete("1.0", "end")
            self.address_list.insert("1.0", "Scanning memory... Please wait\n")
            self.update()

            self.found_addresses = self.magic.memory_search(
                process_id=selected_window.process_id,
                desired_value=value,
                search_addresses=self.found_addresses,
            )
            self.update_address_list()
            self.download_sound(
                "https://github.com/prototbh/TEMP/raw/refs/heads/main/0114.MP3"
            )
            self.play_sound()

        except Exception as e:
            self.address_list.insert("1.0", f"Error: {e}\n")

    def update_address_list(self):
        self.address_list.configure(state="normal")
        self.address_list.delete("1.0", "end")
        self.address_list.insert(
            "1.0", f"Found {len(self.found_addresses)} addresses:\n\n"
        )
        self.address_list.insert(
            "end", "\n".join([f"0x{addr:X}" for addr in self.found_addresses])
        )
        self.address_list.configure(state="disabled")

    def modify_value(self):
        try:
            selected_window = self.get_selected_window()
            if not selected_window:
                return

            address = int(self.modify_address_entry.get(), 16)
            value = int(self.modify_value_entry.get())
            result = self.magic.write_address_value(
                selected_window.process_id, address, value
            )
            self.address_list.insert("1.0", f"{result}\n")
        except Exception as e:
            self.address_list.insert("1.0", f"Error: {e}\n")


if __name__ == "__main__":
    magic = MemoryMagic()
    app = App(magic)
    app.mainloop()
