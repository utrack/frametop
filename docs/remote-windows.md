# Remote application windows (experimental)

Frametop can show individual application windows from an existing KDE Wayland
session as separate VR panels. The application stays on its original computer.
This requires the **KWin Window Stream** host service, a separate project installed
and managed on that computer. It is not included in Frametop's host installers.

Use a Frametop build containing the direct-window receiver. For a source checkout,
build it with `stream/build.sh` using Frametop's normal development container.

## Choose windows

1. Pair a normal Sunshine display from the computer once, using **Frametop Remote
   Displays**. The window receiver reuses that pairing.
2. In the same app, choose **Add windows** next to the computer.
3. Select an application that is already open, then choose **Add window**.
   **Refresh** updates the list after opening or closing applications on the computer.

**Add windows** also works with no panels configured: it checks saved client identities
and reuses one the host still accepts. If all were unpaired, pair a display again first.

Each window gets its own panel. Move, pin, curve and scale it like other Frametop
panels. Resizing it on the host changes its stream and panel dimensions, preserving
its position and text size, with a short pause while capture and decoding restart.

The normal **Connected** switch stops or resumes a window's stream. **Shown** hides
its panel while leaving the stream connected. Removing the panel does not close
the original application. You can disconnect the full desktop display and keep
only the window panels; the paired identity is retained while a panel uses it.
Window streams currently have no audio or clipboard channel.

Connected windows are remembered and reconnect when Frametop starts. The host
needs its normal Plasma login session running. A window's identity lasts only
until that window closes: after restarting its application or the host, remove
the old entry and choose the replacement from **Add windows**.

Pointer and keyboard input activate the original application and share the host's
cursor/focus. Popups and separate dialog windows are not automatically grouped with
their parent; a dialog may need its own panel. Mixed-DPI and multi-monitor input
still need broader testing.

The host service uses authenticated TLS on TCP/14501. Neither selection nor
streaming requires SSH. Configure the host service separately to allow paired
clients to choose application windows.
