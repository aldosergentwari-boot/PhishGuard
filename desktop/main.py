from pathlib import Path
import sys
import tkinter as tk
from tkinter import messagebox, ttk


# Ensure the project root is importable when launched as:
# python desktop/main.py
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.services.hybrid_service import get_hybrid_service


class PhishingDesktopApp:

    BG = "#0b1220"
    PANEL = "#111c2e"
    TEXT = "#e8eef8"
    MUTED = "#9aa9bd"
    GREEN = "#22c55e"
    RED = "#ef4444"
    BLUE = "#3b82f6"

    def __init__(self, root):
        self.root = root
        self.root.title("AI-Based Phishing URL Detection")
        self.root.geometry("820x650")
        self.root.minsize(680, 560)
        self.root.configure(bg=self.BG)

        self.service = None
        self._build_ui()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "TEntry",
            fieldbackground="#172338",
            foreground=self.TEXT,
            insertcolor=self.TEXT,
            padding=10
        )
        style.configure(
            "TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(16, 10)
        )

        header = tk.Frame(self.root, bg=self.BG)
        header.pack(fill="x", padx=28, pady=(24, 12))

        tk.Label(
            header,
            text="PHISHGUARD",
            bg=self.BG,
            fg=self.BLUE,
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w")

        tk.Label(
            header,
            text="AI-Based Phishing URL Detection",
            bg=self.BG,
            fg=self.TEXT,
            font=("Segoe UI", 22, "bold")
        ).pack(anchor="w", pady=(5, 3))

        tk.Label(
            header,
            text="Offline-first ML/local rules with optional online reputation checks.",
            bg=self.BG,
            fg=self.MUTED,
            font=("Segoe UI", 10)
        ).pack(anchor="w")

        scanner = tk.Frame(
            self.root,
            bg=self.PANEL,
            highlightthickness=1,
            highlightbackground="#26364d"
        )
        scanner.pack(fill="x", padx=28, pady=14)

        tk.Label(
            scanner,
            text="Website URL",
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", padx=18, pady=(16, 7))

        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(
            scanner,
            textvariable=self.url_var,
            font=("Segoe UI", 12)
        )
        self.url_entry.pack(fill="x", padx=18, pady=(0, 12))
        self.url_entry.bind("<Return>", lambda _event: self.analyze())

        self.scan_button = tk.Button(
            scanner,
            text="Analyze URL",
            command=self.analyze,
            bg=self.BLUE,
            fg="white",
            activebackground="#2563eb",
            activeforeground="white",
            relief="flat",
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=18,
            pady=10
        )
        self.scan_button.pack(anchor="e", padx=18, pady=(0, 16))

        self.result_frame = tk.Frame(
            self.root,
            bg=self.PANEL,
            highlightthickness=1,
            highlightbackground="#26364d"
        )
        self.result_frame.pack(fill="both", expand=True, padx=28, pady=(0, 24))

        self.status_var = tk.StringVar(value="Ready for offline analysis.")
        tk.Label(
            self.result_frame,
            textvariable=self.status_var,
            bg=self.PANEL,
            fg=self.MUTED,
            font=("Segoe UI", 10)
        ).pack(anchor="w", padx=18, pady=(16, 8))

        self.prediction_var = tk.StringVar(value="No scan yet")
        self.prediction_label = tk.Label(
            self.result_frame,
            textvariable=self.prediction_var,
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Segoe UI", 20, "bold")
        )
        self.prediction_label.pack(anchor="w", padx=18)

        self.risk_var = tk.StringVar(value="Risk score: —")
        tk.Label(
            self.result_frame,
            textvariable=self.risk_var,
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Segoe UI", 13, "bold")
        ).pack(anchor="w", padx=18, pady=(7, 12))

        self.domain_var = tk.StringVar(value="Domain: —")
        tk.Label(
            self.result_frame,
            textvariable=self.domain_var,
            bg=self.PANEL,
            fg=self.MUTED,
            font=("Segoe UI", 10)
        ).pack(anchor="w", padx=18, pady=(0, 12))

        tk.Label(
            self.result_frame,
            text="Detection sources",
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", padx=18)

        self.sources_text = tk.Text(
            self.result_frame,
            height=3,
            wrap="word",
            bg="#0d1727",
            fg=self.TEXT,
            insertbackground=self.TEXT,
            relief="flat",
            font=("Segoe UI", 10),
            padx=10,
            pady=8
        )
        self.sources_text.pack(fill="x", padx=18, pady=(6, 12))
        self.sources_text.configure(state="disabled")

        tk.Label(
            self.result_frame,
            text="Indicators",
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", padx=18)

        self.indicators_text = tk.Text(
            self.result_frame,
            height=5,
            wrap="word",
            bg="#0d1727",
            fg=self.TEXT,
            insertbackground=self.TEXT,
            relief="flat",
            font=("Segoe UI", 10),
            padx=10,
            pady=8
        )
        self.indicators_text.pack(fill="both", expand=True, padx=18, pady=(6, 16))
        self.indicators_text.configure(state="disabled")

    @staticmethod
    def _set_text(widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def analyze(self):
        url = self.url_var.get().strip()

        if not url:
            messagebox.showwarning(
                "URL required",
                "Enter a website address to analyze."
            )
            self.url_entry.focus_set()
            return

        self.scan_button.configure(state="disabled", text="Analyzing...")
        self.status_var.set("Analyzing URL text. The website is not opened or downloaded.")
        self.root.update_idletasks()

        try:
            if self.service is None:
                self.service = get_hybrid_service()

            result = self.service.analyze(url)
            prediction = result["final_prediction"]
            risk = result["final_risk_score"]
            local = result["local_intelligence"]

            self.prediction_var.set(prediction)
            self.prediction_label.configure(
                fg=self.RED if prediction == "PHISHING" else self.GREEN
            )
            self.risk_var.set(f"Risk score: {risk:.2f}%")
            self.domain_var.set(f"Domain: {local.get('domain') or 'Unknown'}")
            self.status_var.set(
                "Analysis completed — online and offline checks"
                if result.get("detection_mode") == "HYBRID_ONLINE_AND_OFFLINE"
                else "Analysis completed — offline checks"
            )

            sources = "\n".join(
                f"• {item}" for item in result.get("decision_sources", [])
            )
            self._set_text(self.sources_text, sources or "No source reported.")

            indicator_lines = []
            for item in result.get("ml_result", {}).get("indicators", []):
                indicator_lines.append(f"ML: {item}")

            for item in local.get("indicators", []):
                indicator_lines.append(
                    f"Local: {item.get('name')}: {item.get('description')}"
                )

            threat = result.get("threat_intelligence", {})
            for provider in threat.get("providers", []):
                indicator_lines.append(
                    f"{provider.get('provider')}: {provider.get('status')}"
                )

            self._set_text(
                self.indicators_text,
                "\n".join(indicator_lines) if indicator_lines
                else "No suspicious indicators were reported."
            )

        except Exception as error:
            self.status_var.set("Analysis failed.")
            messagebox.showerror(
                "Analysis error",
                f"Could not analyze this URL.\n\n{error}"
            )

        finally:
            self.scan_button.configure(
                state="normal",
                text="Analyze URL"
            )


def main():
    root = tk.Tk()
    PhishingDesktopApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
