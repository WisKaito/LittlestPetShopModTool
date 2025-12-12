# -*- coding: utf-8 -*-

import Tkinter as tk
import tkFileDialog
import tkMessageBox
import os
import struct

# Some FSH blocks use 'SHPI@' but others use 'SHPI ' or 'SHPI' + any byte.
# We'll treat any occurrence of the ASCII prefix 'SHPI' followed by ANY single byte as the signature.
SIG_PREFIX = 'SHPI'
SIG_PREFIX_LEN = len(SIG_PREFIX)
TAIL_SCAN = 2048  # scan further back to find name reliably
MAX_NAME_LEN = 128

class FSHBlock(object):
    def __init__(self, offset, raw_data, name, name_end_rel, padding, sig_byte):
        self.offset = offset            # offset in original .str where signature starts
        self.data = raw_data            # full bytes from signature to before next signature
        self.name = name                # extracted name (string)
        self.name_end_rel = name_end_rel  # index within data where name terminator is (end)
        self.padding = padding          # bytes that come after the name terminator but before next signature
        self.sig_byte = sig_byte        # the byte that followed 'SHPI' in original (for preservation)

class LPSModTool(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Littlest Pet Shop Mod Tool")
        self.geometry("1100x650")

        self.str_path = None
        self.blocks = []
        self.original_bytes = None

        self.make_menu()
        self.make_ui()

    def make_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open .str", command=self.open_str)
        file_menu.add_command(label="Save", command=self.save_str)
        file_menu.add_command(label="Save As", command=self.save_as_str)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=lambda: tkMessageBox.showinfo("About", "LPS Mod Tool — Python 2.7 Now accepts any 'SHPI*' signature byte and has improved name extraction."))
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def make_ui(self):
        main = tk.Frame(self)
        main.pack(fill=tk.BOTH, expand=True)

        left = tk.Frame(main)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.listbox = tk.Listbox(left, font=("Courier", 11))
        self.listbox.pack(fill=tk.BOTH, expand=True)

        right = tk.Frame(main)
        right.pack(side=tk.RIGHT, fill=tk.Y)

        self.btn_export = tk.Button(right, text="Export (trimmed)", width=22, command=self.export_fsh)
        self.btn_export.pack(pady=5)
        self.btn_export_raw = tk.Button(right, text="Export (raw block)", width=22, command=self.export_raw)
        self.btn_export_raw.pack(pady=5)
        self.btn_import = tk.Button(right, text="Import (replace)", width=22, command=self.import_fsh)
        self.btn_import.pack(pady=5)
        self.btn_refresh = tk.Button(right, text="Refresh list", width=22, command=self._refresh_list)
        self.btn_refresh.pack(pady=5)

    def open_str(self):
        path = tkFileDialog.askopenfilename(filetypes=[("STR Files", "*.str;*.STR"), ("All files", "*")])
        if not path:
            return
        self.str_path = path
        with open(path, 'rb') as f:
            self.original_bytes = f.read()
        self._parse_blocks()
        self._refresh_list()
        tkMessageBox.showinfo("Loaded", "Loaded %s (%d bytes)" % (os.path.basename(path), len(self.original_bytes)))

    def _parse_blocks(self):
        self.blocks = []
        data = self.original_bytes
        pos = 0
        L = len(data)
        sig_positions = []
        # Find every index where 'SHPI' occurs and there is at least one following byte
        while True:
            idx = data.find(SIG_PREFIX, pos)
            if idx == -1:
                break
            if idx + SIG_PREFIX_LEN < L:
                sig_positions.append(idx)
                pos = idx + SIG_PREFIX_LEN
            else:
                break
        # Build blocks from each signature to the next signature
        for i, start in enumerate(sig_positions):
            end = sig_positions[i+1] if i+1 < len(sig_positions) else L
            block = data[start:end]
            # capture the byte following 'SHPI' if present
            sig_byte = block[SIG_PREFIX_LEN] if len(block) > SIG_PREFIX_LEN else '\x00'
            name, name_end_rel, padding = self._extract_name_and_padding(block)
            self.blocks.append(FSHBlock(start, block, name, name_end_rel, padding, sig_byte))

    def _extract_name_and_padding(self, block):
        # Search last TAIL_SCAN bytes for zero-terminated ASCII name and 4-byte little-endian size before it.
        scan_len = min(len(block), TAIL_SCAN)
        tail = block[-scan_len:]
        null_positions = []
        # find all null byte positions in tail
        for i in range(len(tail)):
            if tail[i] == '\x00':
                null_positions.append(i)
        # iterate from last null backward to find plausible name
        for rel_null in reversed(null_positions):
            name_term_abs = len(block) - scan_len + rel_null
            # scan backward up to MAX_NAME_LEN to find printable name start
            for ns in range(max(0, name_term_abs - MAX_NAME_LEN), name_term_abs):
                segment = block[ns:name_term_abs]
                # check printable ascii
                ok = True
                if len(segment) == 0:
                    ok = False
                else:
                    for ch in segment:
                        if not (32 <= ord(ch) <= 126):
                            ok = False
                            break
                if not ok:
                    continue
                # check for 4 bytes immediately before ns for size
                size_off = ns - 4
                if size_off < 0:
                    continue
                size_bytes = block[size_off:ns]
                if len(size_bytes) != 4:
                    continue
                size_val = struct.unpack('<I', size_bytes)[0]
                # basic validation: size should be <= (name_start - header_length) + some margin
                # We'll accept size_val if it is <= len(block)
                if size_val <= len(block):
                    name_bytes = block[ns:name_term_abs]
                    try:
                        name = ''.join([c for c in name_bytes])
                    except Exception:
                        name = name_bytes
                    padding = block[name_term_abs+1:]
                    return name, name_term_abs, padding
        # fallback: try to extract printable sequence just before last null
        if null_positions:
            rel_null = null_positions[-1]
            name_term_abs = len(block) - scan_len + rel_null
            # gather printable bytes before
            s = []
            k = name_term_abs - 1
            while k >= 0 and len(s) < MAX_NAME_LEN:
                ch = block[k]
                if 32 <= ord(ch) <= 126:
                    s.append(ch)
                    k -= 1
                else:
                    break
            s.reverse()
            name = ''.join(s) if s else 'UNKNOWN'
            padding = block[name_term_abs+1:]
            return name, name_term_abs, padding
        return 'UNKNOWN', None, ''

    def _refresh_list(self):
        self.listbox.delete(0, tk.END)
        for i, b in enumerate(self.blocks):
            info = "%03d: %-28s  offset=0x%08X  len=%6d  pad=%4d  sig=%r" % (i, b.name, b.offset, len(b.data), len(b.padding), b.sig_byte)
            self.listbox.insert(tk.END, info)

    def export_fsh(self):
        sel = self.listbox.curselection()
        if not sel:
            tkMessageBox.showerror("Error", "Select a block first")
            return
        b = self.blocks[sel[0]]
        default = b.name if b.name and b.name != 'UNKNOWN' else 'unknown'
        out = tkFileDialog.asksaveasfilename(defaultextension=".fsh", initialfile=default, filetypes=[("FSH files","*.fsh")])
        if not out:
            return
        # Improved trim: export up to LAST \x00 in the block (real end of FSH)
        # Find last null byte
        last_null = b.data.rfind("\x00")
        if last_null != -1:
            trimmed = b.data[:last_null+1]
        else:
            trimmed = b.data  # fallback
        with open(out, 'wb') as f:
            f.write(trimmed)
        tkMessageBox.showinfo("Exported", "Exported %s (bytes=%d)" % (os.path.basename(out), len(trimmed)))

    def export_raw(self):
        sel = self.listbox.curselection()
        if not sel:
            tkMessageBox.showerror("Error", "Select a block first")
            return
        b = self.blocks[sel[0]]
        default = b.name if b.name and b.name != 'UNKNOWN' else 'unknown'
        out = tkFileDialog.asksaveasfilename(defaultextension=".fsh", initialfile=default, filetypes=[("FSH files","*.fsh")])
        if not out:
            return
        with open(out, 'wb') as f:
            f.write(b.data)
        tkMessageBox.showinfo("Exported", "Exported raw %s (bytes=%d)" % (os.path.basename(out), len(b.data)))

    def import_fsh(self):
        sel = self.listbox.curselection()
        if not sel:
            tkMessageBox.showerror("Error", "Select a block to replace")
            return
        idx = sel[0]
        old = self.blocks[idx]
        path = tkFileDialog.askopenfilename(filetypes=[("FSH files","*.fsh;*.FSH;*.*")])
        if not path:
            return
        with open(path, 'rb') as f:
            new_blob = f.read()
        # If imported blob doesn't begin with 'SHPI', allow user to proceed but warn
        if not new_blob.startswith(SIG_PREFIX):
            if not tkMessageBox.askyesno("Warning", "Imported file does not start with 'SHPI'. Insert anyway?"):
                return
        # preserve padding bytes after name terminator from old block
        padding = old.padding or ''
        # build replacement block: ensure we keep the original signature byte if new_blob uses only 'SHPI' prefix
        # if new_blob starts with 'SHPI' but missing sig-byte, we preserve old.sig_byte
        if len(new_blob) > SIG_PREFIX_LEN and new_blob[SIG_PREFIX_LEN] != old.sig_byte:
            # nothing special — use new_blob as-is
            replacement = new_blob + padding
        else:
            replacement = new_blob + padding
        # update original_bytes by replacing the byte range
        before = self.original_bytes[:old.offset]
        after = self.original_bytes[old.offset + len(old.data):]
        self.original_bytes = before + replacement + after
        # re-parse and refresh
        self._parse_blocks()
        self._refresh_list()
        tkMessageBox.showinfo("Imported", "Replaced block %d with %s" % (idx, os.path.basename(path)))

    def rebuild_str(self):
        # Concatenate blocks.data in order — but original_bytes already reflects replacements
        parts = [b.data for b in self.blocks]
        return ''.join(parts)

    def save_str(self):
        if not self.str_path:
            return self.save_as_str()
        out = self.original_bytes
        with open(self.str_path, 'wb') as f:
            f.write(out)
        tkMessageBox.showinfo("Saved", "Saved %s" % os.path.basename(self.str_path))

    def save_as_str(self):
        path = tkFileDialog.asksaveasfilename(defaultextension=".str", filetypes=[("STR Files","*.str")])
        if not path:
            return
        self.str_path = path
        self.save_str()

if __name__ == "__main__":
    app = LPSModTool()
    app.mainloop()
