# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Media viewer — audio and video playback via Qt Multimedia."""
from __future__ import annotations

import io
import os

from PySide6.QtCore import QBuffer, QIODeviceBase, Qt, QTimer, QUrl
from PySide6.QtGui import QCloseEvent
from PySide6.QtMultimedia import (
    QAudio,
    QAudioFormat,
    QAudioOutput,
    QAudioSink,
    QMediaDevices,
    QMediaPlayer,
)
from PySide6.QtMultimediaWidgets import QVideoWidget
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from crush.core import tempdir

_OGG_MAGIC = b"OggS"
_AMR_MAGIC = b"#!AMR"


def _decode_audio_pcm(data: bytes) -> tuple[bytes, int, int] | str:
    """Decode OGG/Opus/Vorbis/AMR to interleaved signed-16-bit PCM.

    Returns (pcm_bytes, sample_rate, channels), or the reason it failed.
    PyAV bundles FFmpeg on Windows/macOS so no system codec is required.
    """
    try:
        import av  # type: ignore
    except ImportError:
        return "PyAV is not installed"
    try:
        container = av.open(io.BytesIO(data))
        if not container.streams.audio:
            return "no audio stream found"
        stream = container.streams.audio[0]
        rate: int = stream.rate or 48000
        channels: int = min(stream.channels or 1, 2)
        layout = "mono" if channels == 1 else "stereo"
        resampler = av.AudioResampler(format="s16", layout=layout, rate=rate)
        chunks: list[bytes] = []
        for frame in container.decode(stream):
            for out in resampler.resample(frame):
                chunks.append(bytes(out.planes[0]))
        for out in resampler.resample(None):  # flush
            chunks.append(bytes(out.planes[0]))
        return b"".join(chunks), rate, channels
    except Exception as exc:
        return str(exc) or type(exc).__name__


class MediaViewer(QWidget):
    """Viewer for video and audio files using Qt Multimedia.

    OGG/Opus files are decoded via PyAV (bundled FFmpeg) and played through
    QAudioSink — this bypasses platform codec limitations on macOS and Windows
    where AVFoundation/Media Foundation do not support Opus.
    """

    def __init__(self, data: bytes, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tmp_path: str | None = None
        self._pcm_failure = ""
        # PCM backend state
        self._using_pcm = False
        self._sink: QAudioSink | None = None
        self._buf: QBuffer | None = None
        self._pcm_bpm = 0  # bytes per millisecond
        self._pcm_duration_ms = 0
        self._pcm_timer = QTimer()
        self._pcm_timer.setInterval(200)
        self._pcm_timer.timeout.connect(self._update_pcm_position)
        self._build_ui()
        self._load(data)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Video surface (hidden for audio-only PCM playback)
        self._video_widget = QVideoWidget()
        layout.addWidget(self._video_widget, stretch=1)

        # Qt player (used for video and non-OGG audio)
        self._player = QMediaPlayer()
        self._audio = QAudioOutput()
        self._player.setAudioOutput(self._audio)
        self._player.setVideoOutput(self._video_widget)
        self._audio.setVolume(0.8)

        # Controls
        controls = QWidget()
        controls.setFixedHeight(48)
        ctrl_layout = QHBoxLayout(controls)
        ctrl_layout.setContentsMargins(8, 4, 8, 4)
        ctrl_layout.setSpacing(8)

        self._play_btn = QPushButton("Play")
        self._play_btn.setFixedWidth(60)
        self._play_btn.clicked.connect(self._toggle_play)
        ctrl_layout.addWidget(self._play_btn)

        self._position_slider = QSlider(Qt.Orientation.Horizontal)
        self._position_slider.setRange(0, 0)
        self._position_slider.sliderMoved.connect(self._seek)
        ctrl_layout.addWidget(self._position_slider, stretch=1)

        self._time_label = QLabel("0:00 / 0:00")
        ctrl_layout.addWidget(self._time_label)

        layout.addWidget(controls)

        # Why playback failed -- hidden unless it did.
        self._error_label = QLabel()
        self._error_label.setWordWrap(True)
        self._error_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._error_label.setStyleSheet("padding: 4px 8px;")
        self._error_label.hide()
        layout.addWidget(self._error_label)

        # Qt player signals
        self._player.positionChanged.connect(self._on_position_changed)
        self._player.durationChanged.connect(self._on_duration_changed)
        self._player.playbackStateChanged.connect(self._on_state_changed)
        self._player.errorOccurred.connect(self._on_player_error)

    def _load(self, data: bytes) -> None:
        if data[:4] == _OGG_MAGIC or data[:5] == _AMR_MAGIC:
            result = _decode_audio_pcm(data)
            if isinstance(result, tuple):
                pcm, rate, channels = result
                self._start_pcm(pcm, rate, channels)
                return
            # Qt Multimedia may still play it; if not, both reasons are shown.
            self._pcm_failure = result
        # Qt multimedia path (video, MP3, M4A, …)
        tmp = tempdir.named_temporary_file(prefix="crush-media-", suffix=".media")
        tmp.write(data)
        tmp.close()
        self._tmp_path = tmp.name
        self._player.setSource(QUrl.fromLocalFile(self._tmp_path))

    def _start_pcm(self, pcm: bytes, rate: int, channels: int) -> None:
        self._using_pcm = True
        self._video_widget.hide()
        bpm = rate * channels * 2 // 1000  # bytes per millisecond (s16)
        self._pcm_bpm = bpm if bpm > 0 else 1
        self._pcm_duration_ms = len(pcm) // self._pcm_bpm
        self._position_slider.setRange(0, self._pcm_duration_ms)
        self._time_label.setText(f"0:00 / {_ms_to_str(self._pcm_duration_ms)}")

        fmt = QAudioFormat()
        fmt.setSampleRate(rate)
        fmt.setChannelCount(channels)
        fmt.setSampleFormat(QAudioFormat.SampleFormat.Int16)

        self._buf = QBuffer()
        self._buf.setData(pcm)
        self._buf.open(QIODeviceBase.OpenModeFlag.ReadOnly)

        self._sink = QAudioSink(QMediaDevices.defaultAudioOutput(), fmt)
        self._sink.setVolume(0.8)
        self._sink.start(self._buf)  # pull mode
        self._play_btn.setText("Pause")
        self._pcm_timer.start()

    # ------------------------------------------------------------------ #
    # Controls                                                             #
    # ------------------------------------------------------------------ #

    def _toggle_play(self) -> None:
        if self._using_pcm:
            if self._sink is None:
                return
            if self._sink.state() == QAudio.State.ActiveState:
                self._sink.suspend()
                self._pcm_timer.stop()
                self._play_btn.setText("Play")
            else:
                if self._buf and self._buf.atEnd():
                    self._buf.seek(0)
                self._sink.resume()
                self._pcm_timer.start()
                self._play_btn.setText("Pause")
        else:
            if self._player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
                self._player.pause()
            else:
                self._player.play()

    def _seek(self, position_ms: int) -> None:
        if self._using_pcm and self._sink and self._buf:
            was_active = self._sink.state() == QAudio.State.ActiveState
            self._sink.suspend()
            self._buf.seek(position_ms * self._pcm_bpm)
            if was_active:
                self._sink.resume()
        else:
            self._player.setPosition(position_ms)

    # ------------------------------------------------------------------ #
    # Qt player signal handlers                                           #
    # ------------------------------------------------------------------ #

    def _on_position_changed(self, position: int) -> None:
        self._position_slider.setValue(position)
        self._time_label.setText(
            f"{_ms_to_str(position)} / {_ms_to_str(self._player.duration())}"
        )

    def _on_duration_changed(self, duration: int) -> None:
        self._position_slider.setRange(0, duration)

    def _on_player_error(self, _error: QMediaPlayer.Error, error_string: str) -> None:
        lines = [f"Playback failed: {error_string or 'unknown Qt Multimedia error'}"]
        if self._pcm_failure:
            lines.append(f"PyAV decode failed first: {self._pcm_failure}")
        self._error_label.setText("\n".join(lines))
        self._error_label.show()

    def _on_state_changed(self, state: QMediaPlayer.PlaybackState) -> None:
        if state == QMediaPlayer.PlaybackState.PlayingState:
            self._play_btn.setText("Pause")
        else:
            self._play_btn.setText("Play")

    # ------------------------------------------------------------------ #
    # PCM timer handler                                                   #
    # ------------------------------------------------------------------ #

    def _update_pcm_position(self) -> None:
        if self._buf is None:
            return
        pos_ms = self._buf.pos() // self._pcm_bpm
        self._position_slider.setValue(pos_ms)
        self._time_label.setText(
            f"{_ms_to_str(pos_ms)} / {_ms_to_str(self._pcm_duration_ms)}"
        )
        if self._buf.atEnd():
            self._pcm_timer.stop()
            self._play_btn.setText("Play")

    # ------------------------------------------------------------------ #
    # Cleanup                                                             #
    # ------------------------------------------------------------------ #

    def closeEvent(self, event: QCloseEvent) -> None:
        self._pcm_timer.stop()
        if self._sink is not None:
            self._sink.stop()
        self._player.stop()
        if self._tmp_path and os.path.exists(self._tmp_path):
            os.unlink(self._tmp_path)
        super().closeEvent(event)


def _ms_to_str(ms: int) -> str:
    s = ms // 1000
    return f"{s // 60}:{s % 60:02d}"
