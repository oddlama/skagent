# what the popup draws with, and whether it is on the screen

Findings behind two rules of skagent's popup: it draws on the CPU and loads no GPU driver, and the agent asks for nothing before the popup says a prompt is on the screen. Both come from one afternoon on one machine. Sources: that machine's journal, GPUI at `6983685` (`gpui_wgpu/src/wgpu_context.rs`, `gpui_linux/src/linux/wayland/window.rs`, `gpui/src/window.rs`), wgpu `cddb2f5` (30.0.0), Vulkan-Loader 1.4.363 (`loader/loader.c`, `docs/LoaderInterfaceArchitecture.md`), libglvnd 1.7.0 (`src/EGL/libeglvendor.c`).

## what GPUI loads to draw a window

- **Every driver there is.** GPUI creates a wgpu instance for Vulkan and GL and enumerates all adapters before it picks one. For Vulkan the loader opens the library of every driver manifest it finds (`loader_icd_scan`, `loader_scanned_icd_add`); for GL, libglvnd loads every EGL vendor library (`LoadVendors`).
- **Then it picks:** an adapter named by `ZED_DEVICE_ID`, else the one the Wayland compositor draws on (the main device of its dmabuf feedback), else a discrete GPU before an integrated one, Vulkan before GL; the first that can configure the window's surface.
- **So a second GPU is always touched,** whichever is picked. Seen in a VM with a stand-in driver and vendor library that leave a file when loaded: every start of the popup loaded both, 5 of 5 (`checks.vm-pinentry`, with the popup's own environment taken out).
- **A sleeping GPU wakes for it.** On a laptop with an Intel and an NVIDIA GPU (NVIDIA's open kernel module 595.104.02, runtime power management), both popups that started with the GPU asleep were followed by the kernel's `nvidia 0000:01:00.0: Enabling HDA controller` before their PIN was typed. That the popup calls into that driver is in the second crash below: its call trace starts at an `ioctl` of `skagent-pinentr`.

## the afternoon (2026-11-20, kernel 6.18.58)

The machine had been up for days and its memory was fragmented: page allocation failures of order 6 and 7 from 11:18 on (iwlwifi among them), with 2.4 GB free and no free block of 512 kB. Every wake of the NVIDIA GPU that day, ten of them, most caused by other programs, logged `NV_ERR_NO_MEMORY` from the driver.

| time | what happened |
| --- | --- |
| 15:25:41 | `skagent load` starts the popup; the NVIDIA GPU wakes. This time the driver fails to allocate a buffer it frees on the way back to sleep (`kccuStateLoad_IMPL: Failed to init device shared buffer`). |
| 15:26:04 | The GPU goes back to sleep: a NULL pointer dereference in `nv_free_kernel_mapping`, from `nv_pmops_runtime_suspend` (kernel oops #1). The worker dies in the middle of the driver, its state left as it was. |
| 15:28:41 | `age -d -j skagent` starts the popup. The agent has the PIN cached, sends the touch state and asks the security key, which blinks. |
| 15:28:44 | The popup's first call into the NVIDIA driver (the version check its library does when loaded) runs into what oops #1 left: a page fault in `_mapInsertBase`, on the dead worker's stack (oops #2). The kernel ends the popup's main thread, `with irqs disabled` and `preempt_count 1`: inside a spinlock of the driver. |
| 15:28:48 | The user touches the blinking key. Nothing is on the screen: the popup's process is still there, its other threads read the agent's messages, and nothing draws. The agent can't tell. |
| 15:28:56 | The agent closes the popup, which doesn't leave, and kills it after 8 s. |
| later | The same command again. The machine freezes and nothing reaches the journal: the next call into the driver waits for the spinlock that oops #2 left locked, with interrupts off. |

The crashes are the NVIDIA driver's: it doesn't survive a failed allocation while resuming. skagent's part was to call into that driver at all, for a window of 360 pixels, and to let a key blink for a prompt that wasn't there.

## what follows for skagent

- **The popup draws on the CPU** (`pinentry/src/rendering.rs`), with Mesa's lavapipe, and nothing else is loaded. The loaders take this through their environment alone, read when they are loaded, so the popup starts itself again with it if it has to:
  - `VK_LOADER_DRIVERS_SELECT=lvp_icd.*`: the Vulkan loader (1.3.234 or newer) skips every driver whose manifest's file name doesn't match, before it would open its library.
  - `VK_LOADER_LAYERS_DISABLE=~all~`, and no `VK_LOADER_LAYERS_ALLOW`: no layer is loaded either. NVIDIA's device-switching layer lives in the same library as its driver, and overlays or capture layers have no business in a PIN prompt.
  - `__EGL_VENDOR_LIBRARY_FILENAMES` set and empty: libglvnd then loads the vendors listed, none, instead of looking for them. wgpu is left with Vulkan.
  - `LIBGL_ALWAYS_SOFTWARE=true`, for an EGL that isn't libglvnd's.
- **With that, in the VM:** no stand-in driver or vendor library is loaded by any popup, the popup reports `llvmpipe`, and its window opens 80 to 260 ms after the first state arrives. The pictures in the README were always drawn this way.
- **What it costs:** the popup needs Mesa's software Vulkan driver (in Mesa's package on NixOS, `vulkan-swrast` or `mesa-vulkan-drivers` elsewhere), and drawing takes CPU time: 1.4 s of it over the first 3.4 s of a popup on average, starting included (69 popups of `nix build .#screenshots`, in a VM at twice the size, 720 pixels square).
- **The agent waits for `SHOWN`** (`skagent-popup`, protocol version 2; `PopupSession::show_visibly`): the popup says when a state is on the screen, and before that no security key is asked for a touch and no answer is taken. The popup says it once the state has faded in and the display server asked for the frame after that one, which it only does for a window it shows. A popup that hasn't said so after 10 s is ended, and the request fails.
- **Seen with the real popup:** behind a lock screen (swaylock) it draws and never says `SHOWN`; the request fails after 10 s and the key is never asked.

Not looked at: a real machine with two GPUs after the change, a Vulkan loader older than 1.3.234 (the popup then warns that it draws on a GPU), and an EGL library that isn't libglvnd's.
