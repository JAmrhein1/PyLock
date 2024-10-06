# splash_screen.py

import os
from tkinter import Toplevel, Label, BOTTOM
from PIL import Image, ImageTk, ImageSequence
from utils import resource_path

class SplashScreen:
    def __init__(self, root, on_close_callback):
        self.root = root
        self.on_close_callback = on_close_callback
        self.splash_root = Toplevel()
        self.splash_root.overrideredirect(True)
        self.splash_root.geometry("500x600")
        self.splash_root.configure(bg="#2C3E50")
        self.splash_root.lift()
        self.splash_root.after_idle(self.splash_root.attributes, '-topmost', False)
        self.create_splash_screen()

    def create_splash_screen(self):
        # Center the splash screen
        x = (self.root.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.root.winfo_screenheight() // 2) - (600 // 2)
        self.splash_root.geometry(f"+{x}+{y}")

        # Load animated GIF
        self.lock_frames = []
        self.frame_durations = []
        lock_image = Image.open(resource_path("images/animated_lock.gif"))

        # Ensure the GIF has duration info
        if 'duration' in lock_image.info:
            duration = lock_image.info['duration']
        else:
            duration = 100  # Default to 100ms

        for frame in ImageSequence.Iterator(lock_image):
            frame = frame.resize((200, 200), Image.LANCZOS)
            frame_copy = frame.copy()
            self.lock_frames.append(ImageTk.PhotoImage(frame_copy))
            # Get frame duration (in milliseconds)
            frame_duration = frame.info.get('duration', duration)
            self.frame_durations.append(frame_duration)

        self.lock_label = Label(self.splash_root, bg="#2C3E50")
        self.lock_label.pack(pady=50)

        # PyLock text label
        self.pylock_label = Label(self.splash_root, text="PyLock", fg="#FFFFFF", bg="#2C3E50", font=('Helvetica', 24))
        self.pylock_label.pack(side=BOTTOM, pady=50)
        self.pylock_label.configure(fg=self._fade_color(0))

        self.frame_index = 0
        self.alpha = 0
        self.animate()

    def animate(self):
        # Animate lock icon
        frame = self.lock_frames[self.frame_index]
        self.lock_label.configure(image=frame)
        frame_duration = self.frame_durations[self.frame_index]
        self.frame_index = (self.frame_index + 1) % len(self.lock_frames)

        # Fade-in effect for "PyLock"
        if self.alpha < 255:
            self.alpha += 5
            fade_color = self._fade_color(self.alpha)
            self.pylock_label.configure(fg=fade_color)
        else:
            # After animation completes, destroy splash and call the main app
            self.splash_root.after(1000, self.destroy_splash)
            return

        # Use the frame duration from the GIF
        self.splash_root.after(frame_duration, self.animate)

    def _fade_color(self, alpha):
        # Helper function to calculate fade color
        return f'#{alpha:02x}{alpha:02x}{alpha:02x}'

    def destroy_splash(self):
        self.splash_root.destroy()
        self.on_close_callback()
