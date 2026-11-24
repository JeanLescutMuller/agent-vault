"""Typing into the agent's Chrome tab (DESIGN.md §8): the tab check, then one JavaScript-for-Automation script that runs a small
script in the page.

Chrome is addressed by its process ID: the main Chrome (started without its own --user-data-dir: the one holding Jean's
profiles), never a Chrome a script started (sandbox, 2026-11-21: `tell application "Google Chrome"` reached the old password
layer's Chrome, which has no window). The tab is found by its id, the same number as Claude in Chrome's tab id [verified
2026-11-21]. The value travels only through osascript's stdin (never an argument: any program sees those with `ps`), then
into the page's field; the reply says what happened, never the value. Needs Chrome's "Allow JavaScript from Apple Events"
(View → Developer) in the agent profile; Jean's own profile keeps it off, so no script can run there.
Reads: the Chrome kit's open tabs, <AV_CHROME_STATE>/open.json ({tab id: {"session_id", "url", …}}). Writes nothing.
Installed (running as av-vault): both steps that need Jean's login session, the Apple Events and the tab record in his home, go
through /usr/local/agent-vault/bin/vault-type as Jean's user (its sudoers line); the script and the value on its stdin.
"""
import json
import os
import pwd
import subprocess

STATE = os.environ.get("AV_CHROME_STATE") or os.path.expanduser("~/opt/chrome-gateways/state")
TYPER = "/usr/local/agent-vault/bin/vault-type"


def as_jean():
    """The command prefix that runs vault-type as Jean's user, when this runs as av-vault (installed); else None."""
    if pwd.getpwuid(os.geteuid()).pw_name != "av-vault":
        return None
    jean = os.environ.get("AV_JEAN") or ""
    if not jean or jean == "root":
        raise RuntimeError("no Chrome to type into: call vault from Jean's user (an agent's session), not as root")
    return ["sudo", "-n", "-u", jean, TYPER]
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# kind: "username" (the username field before the first password field, or autocomplete=username), "password" (the Nth
# visible password field), "new" (every visible empty password field: new + confirm), "verify" (the fields typed a moment ago
# are still password fields; one turned into clear text is emptied). The page and its same-origin frames are searched; a
# frame from another origin cannot be reached from the page. Returns "ok <n>", "mismatch <n>" (the page changed the value),
# "wrong site", "no field", "clear field" (a password asked in a clear text field), "frame <url>" (the form is in a frame from
# another origin), "swapped <n>" (verify: n fields turned into clear text, emptied).
PAGE_JS = r"""(function(){
var want=__WANT__, v=__VALUE__, nth=__NTH__, kind=__KIND__;
var h=location.hostname.toLowerCase();
if(!(h===want||h.slice(-want.length-1)==='.'+want)) return 'wrong site';
var docs=[document], far=[];
(function walk(d){ [].forEach.call(d.querySelectorAll('iframe,frame'), function(f){
  var r=f.getBoundingClientRect(); if(!(r.width>0&&r.height>0)) return;
  try { if(f.contentDocument && f.contentWindow.location.hostname){ docs.push(f.contentDocument); walk(f.contentDocument); return; } } catch(e){}
  far.push(f.src||''); }); })(document);
function vis(e){var r=e.getBoundingClientRect(), s=e.ownerDocument.defaultView.getComputedStyle(e);
 return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'&&!e.disabled&&!e.readOnly;}
function all(q){var l=[]; docs.forEach(function(d){ l=l.concat([].filter.call(d.querySelectorAll(q),vis)); }); return l;}
if(kind==='verify'){ var n=0; docs.forEach(function(d){ [].forEach.call(d.querySelectorAll('input[data-lv-typed]'), function(e){
  if(e.type!=='password'){ e.value=''; e.dispatchEvent(new Event('input',{bubbles:true})); n++; } e.removeAttribute('data-lv-typed'); }); });
  return n?'swapped '+n:'ok 0'; }
var l, pw=all('input[type=password]');
function said(e){ var t=[e.name,e.id,e.placeholder,e.getAttribute('aria-label'),e.getAttribute('autocomplete')].join(' ');
  if(e.labels) [].forEach.call(e.labels,function(x){t+=' '+x.textContent;}); return t; }
var PASS=/pass(word|wort|e)?|mot.de.passe|kennwort|pwd|\bpin\b/i;
if(kind!=='username' && !pw.length){
  if(all('input[type=text],input:not([type])').some(function(e){return PASS.test(said(e));})) return 'clear field';
  if(far.length) return 'frame '+far[0]; return 'no field'; }
if(kind==='password'){ if(nth>pw.length) return 'no field'; l=[pw[nth-1]]; }
else if(kind==='new'){ l=pw.filter(function(e){return !e.value;}); }
else { l=all('input[autocomplete~=username]');
 if(!l.length){ var c=all('input[type=email],input[type=text],input:not([type])').filter(function(e){return !PASS.test(said(e));});
  if(pw.length) c=c.filter(function(e){return e.compareDocumentPosition(pw[0])&Node.DOCUMENT_POSITION_FOLLOWING;});
  l=c.length?[c[c.length-1]]:[]; } else l=[l[0]]; }
if(!l.length) return far.length?'frame '+far[0]:'no field';
l.forEach(function(e){ var set=Object.getOwnPropertyDescriptor(e.ownerDocument.defaultView.HTMLInputElement.prototype,'value').set;
 e.focus(); set.call(e,v); e.dispatchEvent(new Event('input',{bubbles:true}));
 e.dispatchEvent(new Event('change',{bubbles:true})); e.blur(); if(kind!=='username') e.setAttribute('data-lv-typed','1'); });
var bad=l.filter(function(e){return e.value!==v;}).length;
return (bad?'mismatch ':'ok ')+l.length;
})()"""

# JavaScript for Automation: the tab by its id in the main Chrome; "url" or "run" (the page script above)
JXA = r"""function run() {
  var app = Application(__PID__), want = __TAB__, ws = app.windows();
  for (var i = 0; i < ws.length; i++) {
    var ts = ws[i].tabs();
    for (var j = 0; j < ts.length; j++) {
      if (Number(ts[j].id()) === want) {
        if (__DO__ === 'url') return ts[j].url();
        return app.execute(ts[j], {javascript: __JS__});
      }
    }
  }
  return 'no tab';
}"""


def main_chrome():
    """The process ID of the main Chrome: started without --user-data-dir (scripts' Chromes always give one)."""
    l = []
    for line in subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout.splitlines():
        pid, _, cmd = line.strip().partition(" ")
        if cmd.startswith(CHROME) and "--type=" not in cmd and "--user-data-dir" not in cmd:
            l.append(int(pid))
    if len(l) != 1:
        raise RuntimeError("Chrome is not running" if not l else f"{len(l)} main Chrome processes: nothing typed (tell Jean)")
    return l[0]


def _jxa(tab, do, js=""):
    script = (JXA.replace("__PID__", str(main_chrome())).replace("__TAB__", str(int(tab))).replace("__DO__", json.dumps(do))
              .replace("__JS__", json.dumps(js)))
    pre = as_jean()
    cmd = pre + ["jxa"] if pre else ["/usr/bin/osascript", "-l", "JavaScript", "-"]
    p = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=30)
    if p.returncode:
        err = (p.stderr or "").strip()
        if "JavaScript" in err and ("Apple Events" in err or "AppleScript" in err):
            raise RuntimeError("Chrome refuses: turn on \"Allow JavaScript from Apple Events\" in the agent profile (menu View → "
                               "Developer); Jean does it once")
        raise RuntimeError(f"osascript failed: {err[-200:]}")
    out = p.stdout.strip()
    if out == "no tab":
        raise RuntimeError(f"Chrome has no tab {tab}")
    return out


def entry(tab):
    """The Chrome kit's record of this Claude in Chrome tab: {"session_id", "url", …}; None: not an agent tab."""
    pre = as_jean()
    if pre:
        p = subprocess.run(pre + ["tab", str(int(tab))], capture_output=True, text=True, timeout=15)
        return json.loads(p.stdout) if p.returncode == 0 and p.stdout.strip() else None
    try:
        d = json.load(open(os.path.join(STATE, "open.json")))
    except (OSError, ValueError):
        return None
    return d.get(str(tab))


def locate(tab, session):
    """(the tab's current address, the tab id), after checking it is this session's agent tab (DESIGN.md §8 step 2)."""
    if not str(tab).isdigit():
        raise RuntimeError("<tab> is the Claude in Chrome tab id (a number, from tabs_context_mcp)")
    e = entry(tab)
    if not e:
        raise RuntimeError(f"tab {tab} is not an agent tab the Chrome kit knows: nothing typed (open it with Claude in Chrome first)")
    if e.get("session_id") != session:
        raise RuntimeError(f"tab {tab} belongs to another session ({(e.get('session_id') or '?')[:8]}): nothing typed")
    url = _jxa(tab, "url")
    if not url.startswith(("https://", "http://")):
        raise RuntimeError(f"tab {tab} shows no web page: navigate it to the login page first")
    return url, int(tab)


def fill(where, want, value, kind, nth=1):
    """Set the field(s) of `kind` in the tab to value, if the page is on the website `want` (a registrable domain)."""
    js = (PAGE_JS.replace("__WANT__", json.dumps(want)).replace("__VALUE__", json.dumps(value))
          .replace("__NTH__", str(int(nth))).replace("__KIND__", json.dumps(kind)))
    return _jxa(where[1], "run", js)
