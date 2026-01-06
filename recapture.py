import os
import sys
import hashlib
import json
import datetime
import time
import binascii
import re
import platform
import socket

# --- CORE LIBRARIES ---
try:
    import pytsk3
except ImportError:
    pytsk3 = None

try:
    import pyewf
except ImportError:
    pyewf = None

try:
    import pybde
except ImportError:
    pybde = None

# --- CONFIG ---
MAGIC_SIGS = {
    "jpg": "FFD8FF", "jpeg": "FFD8FF", "png": "89504E47", "gif": "47494638",
    "pdf": "25504446", "zip": "504B0304", "docx": "504B0304", "xlsx": "504B0304",
    "pptx": "504B0304", "jar": "504B0304", "exe": "4D5A", "dll": "4D5A",
    "sys": "4D5A", "rar": "52617221", "7z": "377ABCAF", "bmp": "424D", "mp3": "494433"
}

ZIP_CONTAINERS = {"zip", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "jar", "apk", "odt", "ods", "odp"}
EXE_CONTAINERS = {"exe", "dll", "sys", "drv", "ocx"}

# --- NETWORK OPTIMIZATION ---
CHUNK_SIZE = 16 * 1024 * 1024  
LOG_BUFFER = [] 

class Node:
    def __init__(self):
        self.name = ""; self.path = ""; self.is_dir = False; self.is_deleted = False
        self.size = 0; self.date = ""; self.md5 = ""; self.hex_head = ""; self.bad_sig = False
        self.suggested_ext = ""; self.flagged = False; self.children = []; self.parent = None
        self.sha1 = ""; self.keywords = [] 

# --- WRAPPERS ---
class EWFImgInfo(pytsk3.Img_Info if pytsk3 else object):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)
    def get_size(self):
        return self._ewf_handle.get_media_size()

class BDEImgInfo(pytsk3.Img_Info if pytsk3 else object):
    def __init__(self, bde_volume):
        self._volume = bde_volume
        super(BDEImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    def read(self, offset, size):
        return self._volume.read_at_offset(offset, size)
    def get_size(self):
        return self._volume.get_size()

# --- UTILS ---
def log_msg(msg, callback=None):
    timestamp = datetime.datetime.now().strftime("[%H:%M:%S]")
    clean_msg = f"{timestamp} {msg}"
    LOG_BUFFER.append(clean_msg)
    if callback: callback(msg)
    else: print(msg)

def log_system_info(target, callback, kw_list):
    timestamp = datetime.datetime.now().strftime('%d-%m-%Y %H:%M')
    log_msg("-" * 60, callback)
    # UPDATED VERSION STRING
    log_msg(f"RECAPTURE v1.0 | FORENSIC AUDIT LOG", callback)
    log_msg("-" * 60, callback)
    log_msg(f"Date/Time  : {timestamp}", callback)
    log_msg(f"Workstation: {socket.gethostname()} ({platform.system()} {platform.release()})", callback)
    log_msg(f"Target Path: {target}", callback)
    
    missing = []
    if not pytsk3: missing.append("pytsk3 (Required for Images)")
    if not pyewf: missing.append("pyewf (Using TSK for E01)")
    
    if missing:
        log_msg("WARNING: Libraries Status:", callback)
        for m in missing: log_msg(f"  [!] {m}", callback)
    else:
        log_msg("Drivers    : Forensic Drivers Loaded (TSK)", callback)

    log_msg(f"Hashing    : MD5 + SHA-1", callback)
    if kw_list:
        log_msg(f"Keywords   : {len(kw_list)} terms loaded", callback)
    log_msg("-" * 60, callback)

def detect_os(fs):
    try:
        if fs.open_dir("/Windows"): return "Windows (Modern)"
    except: pass
    try:
        if fs.open_dir("/WINNT"): return "Windows (Legacy)"
    except: pass
    try:
        if fs.open_dir("/System/Library/CoreServices"): return "macOS / OSX"
    except: pass
    try:
        if fs.open_dir("/Users") and fs.open_dir("/Applications"): return "macOS / OSX (User Root)"
    except: pass
    try:
        if fs.open_dir("/etc") and fs.open_dir("/bin"): return "Linux / Unix"
    except: pass
    return "Storage Drive / Unknown OS"

def format_date(ts):
    if not ts: return ""
    try: return datetime.datetime.fromtimestamp(ts).strftime("%d-%m-%Y %H:%M")
    except: return ""

def get_hashes(path, callback=None):
    hashes = set()
    if not path: return hashes
    try:
        log_msg(f"[*] Loading Hash Database: {os.path.basename(path)}", callback)
        with open(path, 'r') as f:
            for line in f:
                h = line.strip().lower()
                if h: hashes.add(h)
        log_msg(f"    > Loaded {len(hashes)} signatures.", callback)
    except: pass
    return hashes

def check_sig(name, hex_str):
    if not hex_str or len(hex_str) < 4: return False, ""
    name = name.lower(); ext = name.split(".")[-1] if "." in name else ""
    detected_type = "Unknown"; is_mismatch = False
    for sig, type_name in MAGIC_SIGS.items():
        if hex_str.startswith(sig):
            detected_type = type_name.upper(); break
            
    if detected_type == "ZIP":
        if ext in ZIP_CONTAINERS or ext == "zip": is_mismatch = False
        else: is_mismatch = True
    elif detected_type == "EXE":
        if ext in EXE_CONTAINERS: is_mismatch = False
        else: is_mismatch = True
    elif detected_type != "Unknown":
        if ext != detected_type.lower():
            if detected_type == "JPG" and ext == "jpeg": is_mismatch = False
            else: is_mismatch = True

    if detected_type == "Unknown": return False, ""
    return is_mismatch, detected_type

def count_files_fast(path, callback):
    log_msg("[*] Pre-Scan Analysis: Indexing file structure...", callback)
    total = 0
    try:
        for root, dirs, files in os.walk(path):
            total += len(files) + len(dirs)
            if total % 5000 == 0: 
                if callback: callback(f"Indexing... ({total} objects found)|||Calculating...", -1)
    except: pass
    log_msg(f"    > Index Complete. Total Objects: {total}", callback)
    return total

def count_folders_in_tree(nodes):
    count = 0
    for n in nodes:
        if n.is_dir:
            count += 1
            if n.children: count += count_folders_in_tree(n.children)
    return count

def check_encryption_header(img_info, offset, callback):
    try:
        header = img_info.read(offset, 16)
        if b"-FVE-FS-" in header:
            log_msg(f"[!] CRITICAL: BitLocker Encryption Detected (Offset: {offset})", callback)
            log_msg("    > Status: Locked / Unsupported Version", callback)
            log_msg("    > Action: Skipping partition.", callback)
            return True 
    except Exception as e: pass
    return False 

def format_eta(start_time, current, total):
    if current == 0: return "--:--"
    elapsed = time.time() - start_time
    if elapsed < 1: return "--:--"
    rate = current / elapsed
    remaining_files = total - current
    if remaining_files < 0: remaining_files = 0
    eta_seconds = int(remaining_files / rate)
    return str(datetime.timedelta(seconds=eta_seconds))

def scan_file_content(f_obj, size, keyword_list_bytes=None, is_local=False):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    found_keywords = set()
    chunk_size = CHUNK_SIZE 
    overlap_size = 256
    prev_chunk_tail = b""
    try:
        if is_local: f = open(f_obj, "rb")
        else: f = f_obj; offset = 0
        while True:
            if is_local:
                data = f.read(chunk_size)
                if not data: break
            else:
                if offset >= size: break
                read_len = min(chunk_size, size - offset)
                data = f.read_random(offset, read_len)
                if not data: break
                offset += len(data)
            md5.update(data); sha1.update(data)
            if keyword_list_bytes:
                search_buffer = prev_chunk_tail + data
                for kw in keyword_list_bytes:
                    if kw in search_buffer:
                        try: found_keywords.add(kw.decode('utf-8', 'ignore'))
                        except: found_keywords.add(str(kw))
                prev_chunk_tail = data[-overlap_size:] if len(data) > overlap_size else data
        if is_local: f.close()
        return md5.hexdigest(), sha1.hexdigest(), list(found_keywords)
    except: return "", "", []

def process_local_folder(path, hash_db, callback, stats, skip_hash, keyword_bytes):
    root = Node(); root.name = os.path.basename(path) or path; root.path = path; root.is_dir = True
    stack = [(root, path)]
    log_msg(f"[*] Starting Recursive Scan: {path}", callback)
    all_files_list = []
    start_time = time.time()
    while stack:
        parent_node, current_path = stack.pop(0)
        try:
            with os.scandir(current_path) as it:
                for entry in it:
                    stats[1] += 1
                    if stats[1] % 50 == 0 and callback:
                        pct = int((stats[1] / stats[0]) * 100) if stats[0] > 0 else 0
                        if pct > 99: pct = 99
                        eta_str = format_eta(start_time, stats[1], stats[0])
                        fname = entry.name
                        if len(fname) > 37: fname = fname[:34] + "..."
                        callback(f"Scanning: {fname}|||{pct}% complete | ETA: {eta_str}", pct)
                    node = Node(); node.name = entry.name; node.path = entry.path
                    all_files_list.append(node)
                    try: stat = entry.stat(); node.size = stat.st_size; node.date = format_date(stat.st_mtime)
                    except: pass 
                    if entry.is_dir(): node.is_dir = True; parent_node.children.append(node); stack.append((node, entry.path))
                    else:
                        try:
                            with open(entry.path, "rb") as f:
                                head = f.read(16); node.hex_head = binascii.hexlify(head).decode('utf-8').upper()
                                is_bad, suggestion = check_sig(node.name, node.hex_head)
                                if is_bad: node.bad_sig = True; node.suggested_ext = suggestion
                        except: pass
                        if not skip_hash:
                            m, s, kw = scan_file_content(entry.path, node.size, keyword_bytes, is_local=True)
                            node.md5 = m; node.sha1 = s; node.keywords = kw
                            if m in hash_db: node.flagged = True
                        parent_node.children.append(node)
        except Exception: pass
    return root, all_files_list

def process_image_directory(fs, path, hash_db, callback, stats, skip_hash, keyword_bytes):
    file_list = []
    root = Node(); root.name = path; root.path = path; root.is_dir = True
    dir_map = {path: root}
    log_msg(f"[*] Parsing File System Structure ({path})...", callback)
    start_time = time.time()
    def walk(tsk_directory, parent_path):
        for entry in tsk_directory:
            try:
                stats[1] += 1
                if not hasattr(entry, "info") or not entry.info.name: continue
                n = entry.info.name.name.decode('utf-8', 'ignore')
                if n == "." or n == "..": continue
                if stats[1] % 100 == 0 and callback:
                    pct = int((stats[1] / stats[0]) * 100) if stats[0] > 0 else 0
                    if pct > 99: pct = 99
                    eta_str = format_eta(start_time, stats[1], stats[0])
                    display_name = n
                    if len(display_name) > 37: display_name = display_name[:34] + "..."
                    callback(f"Parsing: {display_name}|||{pct}% complete | ETA: {eta_str}", pct)
                fpath = parent_path + "/" + n; fpath = "/" + n if parent_path == "/" else fpath
                item = Node(); item.name = n; item.path = fpath
                meta = entry.info.meta
                if meta:
                    item.size = meta.size; item.date = format_date(meta.crtime)
                    if meta.type == pytsk3.TSK_FS_META_TYPE_DIR: item.is_dir = True
                    if int(meta.flags) & pytsk3.TSK_FS_META_FLAG_UNALLOC: item.is_deleted = True
                if parent_path in dir_map: dir_map[parent_path].children.append(item)
                if item.is_dir:
                    dir_map[fpath] = item
                    if meta:
                        try: sub = fs.open_dir(inode=meta.addr); walk(sub, fpath)
                        except: pass
                else:
                    if meta and not item.is_deleted:
                        try:
                            tf = fs.open_meta(inode=meta.addr); head = tf.read_random(0, 16)
                            item.hex_head = binascii.hexlify(head).decode('utf-8').upper()
                            is_bad, suggestion = check_sig(item.name, item.hex_head)
                            if is_bad: item.bad_sig = True; item.suggested_ext = suggestion
                        except: pass
                        if not skip_hash:
                            try:
                                tf = fs.open_meta(inode=meta.addr)
                                m, s, kw = scan_file_content(tf, item.size, keyword_bytes, is_local=False)
                                item.md5 = m; item.sha1 = s; item.keywords = kw
                                if item.md5 in hash_db: item.flagged = True
                            except: pass
                    file_list.append(item)
            except: continue
    try: r = fs.open_dir("/"); walk(r, path)
    except Exception as e: log_msg(f"[!] Error reading directory: {e}", callback)
    return root, file_list

def serialize_tree_minified(nodes):
    output = []
    for n in nodes:
        d = {"n": n.name}
        if n.size > 0: d["s"] = n.size
        if n.date: d["d"] = n.date
        if n.md5: d["h"] = n.md5
        if n.sha1: d["h1"] = n.sha1
        if n.keywords: d["kw"] = n.keywords 
        if n.hex_head: d["x"] = n.hex_head
        if n.bad_sig: d["b"] = 1
        if n.suggested_ext: d["sx"] = n.suggested_ext
        if n.is_dir: d["k"] = 1
        if n.flagged: d["f"] = 1
        if n.is_deleted: d["del"] = 1
        if n.children: d["c"] = serialize_tree_minified(n.children)
        output.append(d)
    return output

def generate_html(roots, files, output_path, case_name, examiner_name="", case_ref="", notes=""):
    try:
        log_msg("Generating v1.0 Report...", None)
        full_json = json.dumps(serialize_tree_minified(roots), separators=(',', ':'))
        chunks = [full_json[i:i+32000] for i in range(0, len(full_json), 32000)]
        js_data_array = "[" + ",".join([json.dumps(c) for c in chunks]) + "]"
        timestamp = datetime.datetime.now().strftime("%d-%m-%Y %H-%M-%S")
        
        # VALIDATION COUNTS
        file_count = str(len(files))
        folder_count = str(count_folders_in_tree(roots))
        
        deleted = str(sum(1 for f in files if f.is_deleted))
        alerts = str(sum(1 for f in files if f.flagged))
        mismatches = str(sum(1 for f in files if f.bad_sig))
        kw_hits = str(sum(1 for f in files if f.keywords)) 
        
        meta_parts = [timestamp]
        if examiner_name: meta_parts.insert(0, f"Examiner: {examiner_name}")
        if case_ref: meta_parts.insert(0, f"Ref: {case_ref}")
        header_info = " | ".join(meta_parts)
        
        # Add Validation to Header Info
        validation_info = f"<span style='color:#ccc;margin-left:20px;font-size:11px'>Files: {file_count} | Folders: {folder_count}</span>"
        header_info += validation_info

        notes_html = ""
        if notes:
            safe_notes = notes.replace("\n", "<br>")
            notes_html = f"<div class='notes-box'><div class='notes-title'>Examiner Notes</div><div class='notes-content'>{safe_notes}</div></div>"
        
        html_template = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Report: {{CASE_NAME}}</title>
<style>body{font-family:'Poppins','Segoe UI',sans-serif;margin:0;background:#f5f5f5;color:#333;overflow:hidden}.top-bar{background:#202020;color:#fff;padding:0 20px;height:40px;display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid #007acc}.brand{font-weight:700;letter-spacing:1px}.stats-bar{padding:10px 20px;background:#fff;border-bottom:1px solid #ddd;display:flex;gap:15px;align-items:center;font-size:13px}.filter-btn{background:#eee;border:1px solid #ddd;border-radius:4px;padding:4px 8px;cursor:pointer;font-size:11px;font-weight:600;color:#555}.filter-btn:hover{background:#e0e0e0}.filter-btn.active{background:#007acc;color:#fff;border-color:#005c99}.filter-group{display:flex;gap:5px;border-left:1px solid #ddd;padding-left:15px}.notes-box{background:#fff8e1;border-bottom:1px solid #ffe0b2;padding:10px 20px;font-size:13px;color:#5d4037}.container{display:flex;height:calc(100vh - 160px)}.has-notes .container{height:calc(100vh - 220px)}.tree-view{width:320px;background:#fafafa;border-right:1px solid #ddd;overflow:auto;padding:10px;font-size:13px}.main-view{flex:1;display:flex;flex-direction:column}.file-list{flex:1;overflow:auto;background:#fff;border-bottom:1px solid #ddd}.inspector{height:140px;background:#fcfcfc;padding:10px 20px;display:flex;gap:40px;align-items:flex-start;box-shadow:0 -2px 5px rgba(0,0,0,0.05);overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed}th{background:#f0f0f0;text-align:left;padding:10px;border-bottom:2px solid #ddd;position:sticky;top:0}td{padding:8px 10px;border-bottom:1px solid #eee;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}tr:hover{background:#f0f7ff}.tree-item{display:flex;align-items:center;padding:2px 0}.node{cursor:pointer;padding:2px 6px;white-space:nowrap;overflow:hidden;border-radius:4px;border:1px solid transparent}.node:hover{background:#e0e0e0}.node.selected{background:#cce8ff;border-color:#007acc;color:#004a80}.caret{display:inline-block;width:20px;text-align:center;cursor:pointer;color:#777;font-size:10px}.nested{padding-left:20px;display:none;border-left:1px solid #eee;margin-left:8px}.visible{display:block}.alert{color:#d32f2f!important;font-weight:bold;background:#fff5f5!important}.mismatch{color:#e65100!important;font-weight:bold}.kw-hit{color:#673ab7!important;font-weight:bold}.deleted td{text-decoration:line-through;color:#999}.insp-group{display:flex;flex-direction:column;gap:4px;min-width:150px}.insp-lbl{font-size:11px;color:#888;text-transform:uppercase;font-weight:bold}.insp-val{font-size:14px;font-weight:500;font-family:'Consolas',monospace;word-break:break-all}.hex-val{color:#007acc;letter-spacing:1px}.tag-icon{cursor:pointer;color:#ccc;font-size:14px}.tag-icon.active{color:#ff9800}.footer{height:50px;background:#f8f8f8;border-top:1px solid #ccc;display:flex;flex-direction:column;align-items:center;justify-content:center;font-size:11px;color:#777;text-align:center}.dark body{background:#121212;color:#e0e0e0}.dark .stats-bar{background:#1e1e1e;border-color:#333;color:#ccc}.dark .filter-btn{background:#333;border-color:#444;color:#aaa}.dark .filter-btn.active{background:#007acc;color:#fff}.dark .notes-box{background:#262015;border-color:#3e2723;color:#e0e0e0}.dark .tree-view{background:#1e1e1e;border-color:#333;color:#e0e0e0}.dark .file-list{background:#121212;border-color:#333}.dark .inspector{background:#1e1e1e;box-shadow:none;border-top:1px solid #333}.dark th{background:#252526;color:#e0e0e0;border-color:#333}.dark td{border-color:#2d2d2d;color:#ccc}.dark tr:hover{background:#2a2d3e}.dark .node:hover{background:#333}.dark .node.selected{background:#37373d;color:#fff;border-color:#007acc}.dark .footer{background:#1a1a1a;border-color:#333}}</style></head>
<body class="{{HAS_NOTES_CLASS}}"><div class="top-bar"><div class="brand">RECAPTURE &nbsp;<span style="opacity:0.7">|&nbsp; {{CASE_NAME}}</span></div><div class="meta-info">{{HEADER_INFO}}</div></div><div class="stats-bar"><button class="filter-btn" onclick="document.body.classList.toggle('dark')">Dark Mode</button><div class="filter-group"><button class="filter-btn active" onclick="setFilter('all',this)">Tree View</button><button class="filter-btn" onclick="setFilter('del',this)">Deleted ({{DELETED_COUNT}})</button><button class="filter-btn" onclick="setFilter('bad',this)">Mismatches ({{MISMATCH_COUNT}})</button><button class="filter-btn" onclick="setFilter('kw',this)">Keywords ({{KW_COUNT}})</button><button class="filter-btn" onclick="setFilter('alert',this)">Alerts ({{ALERT_COUNT}})</button><button class="filter-btn" onclick="setFilter('tag',this)">Tagged (<span id="tag_cnt">0</span>)</button></div><span style="flex:1"></span><button class="filter-btn" onclick="exportCSV()" style="margin-right:10px;background:#007acc;color:#ffffff;border-color:#005c99;font-weight:600">Download CSV (Current View)</button><input type="text" id="search" placeholder="Search..." oninput="scheduleSearch()"></div>{{NOTES_HTML}}<div class="container"><div class="tree-view" id="tree">Loading...</div><div class="main-view"><div class="file-list"><table id="tbl"><thead><tr><th width="5%">&#9733;</th><th width="35%">Name</th><th width="10%">Size</th><th width="15%">Date</th><th width="15%">Signature Check</th><th width="20%">MD5</th></tr></thead><tbody id="tbody"></tbody></table></div><div class="inspector"><div class="insp-group"><div class="insp-lbl">Selected File</div><div class="insp-val" id="i_name">-</div></div><div class="insp-group"><div class="insp-lbl">Hashes</div><div class="insp-val" style="font-size:11px">MD5: <span id="i_hash">-</span><br>SHA1: <span id="i_sha">-</span></div></div><div class="insp-group"><div class="insp-lbl">Status / Keywords</div><div class="insp-val" id="i_stat">-</div></div><div class="insp-group"><div class="insp-lbl">Header (Hex)</div><div class="insp-val hex-val" id="i_hex">-</div></div></div></div></div><div class="footer"><div><strong>CONFIDENTIAL FORENSIC REPORT</strong> | Generated by Recapture v1.0</div><div style="font-size:10px;margin-top:3px">DISCLAIMER: For triage use only. Not a full forensic validation.</div></div>
<script>
var dataChunks = {{JSON_DATA_CHUNKS}};
var raw_data = JSON.parse(dataChunks.join(""));
dataChunks = null; 
var selNode=null;var currFilter='all';var currList=[];var flatCache=null;var taggedCount=0;
function getAllFiles(){if(flatCache)return flatCache;var arr=[];var stack=[];raw_data.forEach(r=>stack.push(r));while(stack.length>0){var n=stack.pop();if(!n.k)arr.push(n);if(n.c)for(var i=0;i<n.c.length;i++)stack.push(n.c[i]);}flatCache=arr;return arr;}
function linkParents(nodes,parent){var stack=[];nodes.forEach(n=>stack.push({n:n,p:parent}));while(stack.length>0){var item=stack.pop();item.n.parent=item.p;if(item.n.c){for(var i=0;i<item.n.c.length;i++)stack.push({n:item.n.c[i],p:item.n});}}}
setTimeout(function(){
    linkParents(raw_data,null);
    var t = document.getElementById('tree');
    t.innerHTML = "";
    renderTree(raw_data,t);
    loadTbl(raw_data.length>0?raw_data[0]:raw_data);
},10);
function getIcon(k,n,x,kw){if(kw)return"&#128269; ";if(x)return"&#128123; ";if(k)return"&#128193; ";return"&#128221; ";}
function fmt(s){if(!s)return"";if(s<1024)return s+" B";return(s/1024).toFixed(1)+" KB";}
function highlight(el){if(selNode)selNode.classList.remove('selected');selNode=el;if(selNode)selNode.classList.add('selected');}
function updateInsp(item){document.getElementById('i_name').innerText=item.n;document.getElementById('i_hash').innerText=item.h||"-";document.getElementById('i_sha').innerText=item.h1||"-";document.getElementById('i_hex').innerText=item.x?item.x+"...":"No Data";var stat="Valid";if(item.b)stat="MISMATCH! (Likely: "+(item.sx||"Unknown")+")";else if(item.kw && item.kw.length>0)stat="KEYWORDS FOUND: "+item.kw.join(", ");else if(item.f)stat="HASH ALERT";else if(item.del)stat="DELETED";document.getElementById('i_stat').innerText=stat;document.getElementById('i_stat').style.color=(item.b||item.f||(item.kw&&item.kw.length>0))?"#d32f2f":"#333";}
function toggleTag(item,el){item.tg=!item.tg;if(item.tg)taggedCount++;else taggedCount--;document.getElementById('tag_cnt').innerText=taggedCount;el.innerHTML=item.tg?"&#9733;":"&#9734;";el.className=item.tg?"tag-icon active":"tag-icon";event.stopPropagation();}
function renderTree(nodes,p){nodes.forEach(x=>{var r=document.createElement('div');r.className='tree-item';var a=document.createElement('span');a.className='caret';a.innerHTML=(x.c&&x.c.length>0)?"&#9654;":"&nbsp;";var t=document.createElement('span');t.className='node';t.innerHTML=getIcon(x.k,x.n,x.del,x.kw)+x.n;if(x.kw)t.style.color="#673ab7";else if(x.f||x.b)t.style.color="#d32f2f";if(x.del)t.style.textDecoration="line-through";r.appendChild(a);r.appendChild(t);p.appendChild(r);var s=document.createElement('div');s.className='nested';p.appendChild(s);var d=false;a.onclick=function(){if(x.c){if(!d){renderTree(x.c,s);d=true}s.style.display=(s.style.display==='block')?'none':'block';a.innerHTML=(s.style.display==='block')?"&#9660;":"&#9654;"}};t.onclick=function(){if(currFilter!=='all')setFilter('all',document.querySelector('.filter-group .active'));highlight(t);loadTbl(x)}})}
function loadTbl(n){var b=document.getElementById('tbody');b.innerHTML="";var l=[];if(currFilter==='all')l=Array.isArray(n)?n:(n.c||[n]);else{var all=getAllFiles();if(currFilter==='del')l=all.filter(x=>x.del);else if(currFilter==='bad')l=all.filter(x=>x.b);else if(currFilter==='alert')l=all.filter(x=>x.f);else if(currFilter==='kw')l=all.filter(x=>x.kw && x.kw.length>0);else if(currFilter==='tag')l=all.filter(x=>x.tg);}currList=l;if(currFilter==='all'&&n.parent){var r=document.createElement('tr');r.innerHTML="<td></td><td>&#128193; ..</td><td></td><td></td><td></td><td></td>";r.onclick=function(){loadTbl(n.parent)};b.appendChild(r)}var max=l.length>500?500:l.length;for(var i=0;i<max;i++){var item=l[i];var r=document.createElement('tr');if(item.kw&&item.kw.length>0)r.className='kw-hit';if(item.f)r.className='alert';if(item.b)r.className='mismatch';if(item.del)r.className+=' deleted';var h=item.h?item.h:"";var sig=item.x?"MATCH":"";if(item.b)sig="MISMATCH ("+(item.sx||"?")+")";var tagIcon=item.tg?"&#9733;":"&#9734;";var tagClass=item.tg?"tag-icon active":"tag-icon";var tagHtml=`<span class="${tagClass}" onclick="toggleTag(currList[${i}], this)">${tagIcon}</span>`;r.innerHTML=`<td>${tagHtml}</td><td>${getIcon(item.k,item.n,item.del,item.kw)}${item.n}</td><td>${fmt(item.s)}</td><td>${(item.d||"")}</td><td>${sig}</td><td>${h}</td>`;if(item.k)r.onclick=(function(x){return function(){if(currFilter!=='all')setFilter('all',document.querySelector('.filter-group button'));loadTbl(x)}})(item);else r.onclick=(function(x){return function(){updateInsp(x)}})(item);b.appendChild(r);}if(l.length>500){var r=document.createElement('tr');r.innerHTML="<td colspan='6' style='text-align:center;color:#777'><i>... "+(l.length-500)+" more items ...</i></td>";b.appendChild(r);}}
function setFilter(f,btn){currFilter=f;var btns=document.getElementsByClassName('filter-btn');for(var i=0;i<btns.length;i++)btns[i].classList.remove('active');btn.classList.add('active');if(f==='all')loadTbl(raw_data.length>0?raw_data[0]:raw_data);else loadTbl(null);}
function exportCSV(){var csvContent="data:text/csv;charset=utf-8,Tagged,Name,Size,Date,MD5,SHA1,Status,Keywords\\n";var listToExport=[];if(currFilter==='all'){var stack=[];raw_data.forEach(r=>stack.push(r));while(stack.length>0){var n=stack.pop();listToExport.push(n);if(n.c)n.c.forEach(c=>stack.push(c));}}else{listToExport=currList;}listToExport.forEach(n=>{var stat="";if(n.del)stat="Deleted";if(n.b)stat="SignatureMismatch";if(n.f)stat="HashAlert";if(n.kw&&n.kw.length>0)stat+="|KeywordHit";var tag=n.tg?"Yes":"";var kws=n.kw?n.kw.join(";"):"";csvContent+=tag+","+n.n+","+n.s+","+(n.d||"")+","+(n.h||"")+","+(n.h1||"")+","+stat+","+kws+"\\n";});var encodedUri=encodeURI(csvContent);var link=document.createElement("a");link.setAttribute("href",encodedUri);link.setAttribute("download","Recapture_Export.csv");document.body.appendChild(link);link.click();document.body.removeChild(link);}
var searchTimer;function scheduleSearch(){clearTimeout(searchTimer);searchTimer=setTimeout(doSearch,500);}
function doSearch(){var q=document.getElementById('search').value.toLowerCase();if(!q){currFilter='all';loadTbl(raw_data.length>0?raw_data[0]:raw_data);return;}var rs=[];var stack=[];raw_data.forEach(r=>stack.push(r));while(stack.length>0){var n=stack.pop();if(rs.length>200)break;if(n.n.toLowerCase().includes(q))rs.push(n);if(n.c){for(var i=0;i<n.c.length;i++)stack.push(n.c[i]);}}var b=document.getElementById('tbody');b.innerHTML="";rs.forEach(i=>{var r=document.createElement('tr');var h=i.h?i.h:"";r.innerHTML=`<td></td><td>${getIcon(i.k,i.n,i.del)}${i.n}</td><td>${fmt(i.s)}</td><td>${(i.d||"")}</td><td>${(i.b?"MISMATCH ("+(i.sx||"?")+")":"")}</td><td>${h}</td>`;r.onclick=function(){if(i.parent)loadTbl(i.parent);else updateInsp(i);};b.appendChild(r)})}
</script></body></html>"""
    
        html = html_template.replace("{{CASE_NAME}}", case_name) \
                            .replace("{{HEADER_INFO}}", header_info) \
                            .replace("{{HAS_NOTES_CLASS}}", 'has-notes' if notes else '') \
                            .replace("{{NOTES_HTML}}", notes_html) \
                            .replace("{{FOLDER_COUNT}}", folder_count) \
                            .replace("{{FILE_COUNT}}", file_count) \
                            .replace("{{DELETED_COUNT}}", deleted) \
                            .replace("{{MISMATCH_COUNT}}", mismatches) \
                            .replace("{{ALERT_COUNT}}", alerts) \
                            .replace("{{KW_COUNT}}", kw_hits) \
                            .replace("{{JSON_DATA_CHUNKS}}", js_data_array)

        with open(output_path, "w", encoding='utf-8') as f: f.write(html)
        
        # LOGGING FINAL STATS
        log_msg(f"[+] Validation: {file_count} Files | {folder_count} Folders processed.", None)
        
    except Exception as e:
        log_msg(f"Critical Error generating report: {e}", None)

def run_recapture(target_path, output_path, hash_list=None, log_callback=None, skip_hash=False, examiner_name="", case_ref="", notes="", key_callback=None, keywords=None):
    kw_bytes = []
    if keywords:
        for k in keywords.split("\n"):
            k = k.strip()
            if k: kw_bytes.append(k.encode('utf-8'))
            
    log_system_info(target_path, log_callback, kw_bytes)
    hashes = get_hashes(hash_list, log_callback)
    
    if os.path.isdir(target_path):
        log_msg("Scanning Local Directory...", log_callback)
        total = count_files_fast(target_path, log_callback)
        root, files = process_local_folder(target_path, hashes, log_callback, [total, 0], skip_hash, kw_bytes)
        generate_html([root], files, output_path, os.path.basename(target_path), examiner_name, case_ref, notes)
        return
    
    if not pytsk3:
        log_msg("[!] CRITICAL ERROR: 'pytsk3' library not found.", log_callback)
        log_msg("    > Cannot parse E01/Image files without this driver.", log_callback)
        log_msg("    > Please install it using: pip install pytsk3", log_callback)
        log_msg("    > Scan Aborted.", log_callback)
        return

    target_path = os.path.normpath(os.path.abspath(target_path)); ext = os.path.splitext(target_path)[1].lower(); img_info = None
    log_msg(f"Loading Image: {os.path.basename(target_path)}", log_callback)
    
    # --- E01 SUPPORT ---
    if ext == ".e01" and pyewf:
        try:
            filenames = pyewf.glob(target_path); ewf_handle = pyewf.handle(); ewf_handle.open(filenames); img_info = EWFImgInfo(ewf_handle)
        except: pass
    
    if img_info is None:
        try: img_info = pytsk3.Img_Info(target_path)
        except: return
    
    master_root = Node(); master_root.name = f"Image ({os.path.basename(target_path)})"; master_root.path = "/"; master_root.is_dir = True; partition_roots = []; all_files = []
    found_partitions = False
    
    try:
        vol = pytsk3.Volume_Info(img_info)
        part_count = 0
        for part in vol:
            if part.len > 2048 and "Unallocated" not in part.desc.decode('utf-8','ignore'):
                part_count += 1
                found_partitions = True
                try:
                    off = part.start * vol.info.block_size
                    desc_str = part.desc.decode('utf-8', 'ignore').strip()
                    
                    # LOGGING
                    log_msg(f"Partition {part_count} ({desc_str}) at Offset {off}...", log_callback)
                    
                    is_encrypted = check_encryption_header(img_info, off, log_callback)
                    if not is_encrypted:
                        fs = pytsk3.FS_Info(img_info, offset=off)
                        
                        # --- SMART NAMING (FTK STYLE) ---
                        p_name = f"Partition {part_count} [{desc_str}]"
                        
                        # --- OS & FS DETECTION ---
                        os_name = detect_os(fs)
                        fs_type = str(fs.info.ftype).replace("TSK_FS_TYPE_", "")
                        log_msg(f"  > File System: {fs_type}", log_callback)
                        log_msg(f"  > Detected OS: {os_name}", log_callback)
                        
                        if os_name != "Storage Drive / Unknown OS":
                            p_name += f" ({os_name})"
                        
                        try: total = (fs.info.last_inum - fs.info.first_inum) / 2
                        except: total = 50000
                        r, f = process_image_directory(fs, p_name, hashes, log_callback, [total,0], skip_hash, kw_bytes)
                        partition_roots.append(r); all_files += f
                    else:
                        locked_node = Node(); locked_node.name = f"Partition {part_count} [LOCKED]"; locked_node.is_dir = True; partition_roots.append(locked_node)
                except Exception as e: continue
    except: pass

    if not found_partitions or len(partition_roots) == 0:
        log_msg("No partitions. Scanning raw...", log_callback)
        try:
            if not check_encryption_header(img_info, 0, log_callback):
                fs = pytsk3.FS_Info(img_info)
                # Raw Scan OS Check
                os_name = detect_os(fs)
                fs_type = str(fs.info.ftype).replace("TSK_FS_TYPE_", "")
                log_msg(f"  > File System: {fs_type}", log_callback)
                log_msg(f"  > Detected OS: {os_name}", log_callback)
                
                r, f = process_image_directory(fs, "Root", hashes, log_callback, [50000,0], skip_hash, kw_bytes)
                partition_roots.append(r); all_files += f
        except: pass

    master_root.children = partition_roots
    generate_html([master_root], all_files, output_path, os.path.basename(target_path), examiner_name, case_ref, notes)
    log_msg(f"Done! Report: {output_path}", log_callback)