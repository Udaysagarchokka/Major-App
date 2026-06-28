"""
main.py  (Android / Kivy version)
Same core logic as the desktop app — key_manager, qr_generator,
qr_verifier, ai_phishing — wrapped in a Kivy UI so it can be packaged
into a free Android APK with Buildozer.

This version lets the user pick an existing QR image to verify (via
Android's native file picker through plyer) and generate a secure QR
from typed text. Live camera scanning can be added later with the
`pyzbar`-free OpenCV detector already used in qr_verifier.py, once you
are comfortable with Kivy's Camera widget and Android camera permissions.
"""

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup

from key_manager import generate_keypair, keys_exist
from qr_generator import create_secure_qr, upgrade_existing_qr
from qr_verifier import verify_qr

try:
    from plyer import filechooser
except ImportError:
    filechooser = None


class SecureScanApp(App):
    def build(self):
        if not keys_exist():
            generate_keypair()

        root = BoxLayout(orientation="vertical", padding=20, spacing=15)

        root.add_widget(Label(text="SecureScan", font_size=24, size_hint=(1, 0.2)))

        self.data_input = TextInput(
            hint_text="Data to embed (for Generate) or issuer ID (for Upgrade)",
            size_hint=(1, 0.15),
            multiline=False,
        )
        root.add_widget(self.data_input)

        generate_btn = Button(text="Generate Secure QR", size_hint=(1, 0.15))
        generate_btn.bind(on_press=self.on_generate)
        root.add_widget(generate_btn)

        upgrade_btn = Button(text="Upgrade Existing QR to Secure", size_hint=(1, 0.15))
        upgrade_btn.bind(on_press=self.on_upgrade)
        root.add_widget(upgrade_btn)

        verify_btn = Button(text="Verify a QR Image", size_hint=(1, 0.15))
        verify_btn.bind(on_press=self.on_verify)
        root.add_widget(verify_btn)

        self.status_label = Label(text="", size_hint=(1, 0.3))
        root.add_widget(self.status_label)

        return root

    def on_generate(self, instance):
        data = self.data_input.text.strip()
        if not data:
            self.show_popup("Error", "Please enter some data first.")
            return

        output_path = "secure_qr.png"
        create_secure_qr(data=data, issuer_id="merchant_demo_001", output_path=output_path)
        self.show_popup("Done", f"Secure QR saved as {output_path}")

    def on_verify(self, instance):
        if filechooser is None:
            self.show_popup("Error", "File picker not available on this platform.")
            return
        self._picker_mode = "verify"
        filechooser.open_file(on_selection=self.handle_selection)

    def on_upgrade(self, instance):
        if filechooser is None:
            self.show_popup("Error", "File picker not available on this platform.")
            return
        self._picker_mode = "upgrade"
        filechooser.open_file(on_selection=self.handle_selection)

    def handle_selection(self, selection):
        if not selection:
            return
        image_path = selection[0]
        mode = getattr(self, "_picker_mode", "verify")

        if mode == "upgrade":
            issuer_id = self.data_input.text.strip() or "merchant_demo_001"
            try:
                result = upgrade_existing_qr(
                    image_path, issuer_id=issuer_id, output_path="secure_qr_upgraded.png"
                )
            except Exception as e:
                self.show_popup("Error", str(e))
                return
            note = "already signed, re-signed" if result["was_already_secure"] else "was a normal, unsigned QR"
            message = (
                f"New secure QR saved as secure_qr_upgraded.png\n"
                f"Original data: {result['original_data']}\n"
                f"({note})"
            )
            self.show_popup("Upgrade complete", message)
            return

        try:
            result = verify_qr(image_path)
        except Exception as e:
            self.show_popup("Error", str(e))
            return

        message = (
            f"Verdict: {result['verdict']}\n"
            f"Reason: {result['reason']}\n"
            f"Signature valid: {result['signature_valid']}\n"
            f"Phishing score: {result['phishing_score']}"
        )
        self.show_popup("Verification result", message)

    def show_popup(self, title, message):
        popup = Popup(
            title=title,
            content=Label(text=message),
            size_hint=(0.85, 0.5),
        )
        popup.open()


if __name__ == "__main__":
    SecureScanApp().run()
