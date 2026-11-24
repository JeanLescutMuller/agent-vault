"""The first net on every reply (DESIGN.md §6): every 6-character piece of each password the daemon handled this run.

Catches a site that shows part of a password, or a "show password" eye; the second net is masking (masking.py), which knows
every secret of the vault but only by 12-character pieces. Reads and writes nothing: the pieces live in memory only.
"""
import base64
import urllib.parse


class Secrets:
    """The passwords the daemon knows: every 6-char piece of each, case-insensitive. Nothing else: mail codes, links and
    temporary values are short-lived (Jean, 2026-10-22)."""
    W = 6

    def __init__(self):
        self.s_piece = set()

    def add_pw(self, s):
        # as made, URL-encoded (a page that puts it in a link: %23 for #) and in base64 (at the 3 places it can start in a
        # longer base64 string, the edges dropped), so a page cannot show it in those forms either (audit, 2026-10-24)
        if not s:
            return
        l_form = [s, urllib.parse.quote(s, safe="")]
        for k in range(3):
            for enc in (base64.b64encode, base64.urlsafe_b64encode):
                l_form.append(enc(b"\0" * k + s.encode()).decode()[(4 * k + 2) // 3 + 1:-3])
        for f in l_form:
            self.s_piece.update(f[i:i + self.W].lower() for i in range(len(f) - self.W + 1))

    def forget(self):
        self.s_piece.clear()

    def spans(self, text):
        low, l_sp = text.lower(), []
        for i in range(len(low) - self.W + 1):
            if low[i:i + self.W] in self.s_piece:
                l_sp.append((i, i + self.W))
        return l_sp

    def found(self, text):
        return bool(text) and bool(self.spans(text))

    def scrub(self, text):
        if not text:
            return text
        l_sp = sorted(self.spans(text))
        if not l_sp:
            return text
        l_out, pos, (a, b) = [], 0, l_sp[0]
        for c, d in l_sp[1:] + [(len(text) + 1, len(text) + 1)]:
            if c <= b:  # overlapping pieces: one [hidden] for the whole run
                b = max(b, d)
                continue
            l_out += [text[pos:a], "[hidden]"]
            pos, (a, b) = b, (c, d)
        return "".join(l_out) + text[pos:]


SEC = Secrets()
