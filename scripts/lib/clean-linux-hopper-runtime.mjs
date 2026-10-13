import { readFile, readdir, stat } from "node:fs/promises";
import { basename } from "node:path";

/**
 * Observe leftover demo processes on a dedicated clean Linux runner, including
 * groups reparented after their launcher exits. This is not ownership proof and
 * never authorizes signaling; unrelated runtime processes also block this lane.
 */
export const assertCleanLinuxHopperRuntime = async (
  launcherPaths = [
    "/opt/hopper/bin/Hopper",
    ...(process.env.HOPPER_LAUNCHER_PATH === undefined
      ? []
      : [process.env.HOPPER_LAUNCHER_PATH]),
  ],
) => {
  const launchers = [];
  for (const path of launcherPaths) {
    try {
      launchers.push(await stat(path, { bigint: true }));
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  // /proc exposes the executed file even when argv[0] names a removed symlink.
  // Compare file identity, not a display path or a process name.
  let inspectionError;
  for (const entry of await readdir("/proc", { withFileTypes: true })) {
    if (!entry.isDirectory() || !/^\d+$/u.test(entry.name)) continue;
    let retainedRuntime;
    try {
      // procfs preserves argument boundaries. A caller merely mentioning a
      // runtime in its script text or other arguments is not that runtime.
      const arguments_ = (
        await readFile(`/proc/${entry.name}/cmdline`, "utf8")
      ).split("\0");
      retainedRuntime =
        arguments_[0] === "/opt/hopper/bin/Hopper" ||
        basename(arguments_[0] ?? "") === "Xvfb" ||
        (basename(arguments_[0] ?? "") === "python3" &&
          basename(arguments_[1] ?? "") === "hopper-demo-x11.py");
      if (!retainedRuntime && launchers.length > 0) {
        const executable = await stat(`/proc/${entry.name}/exe`, {
          bigint: true,
        });
        retainedRuntime = launchers.some(
          ({ dev, ino }) => dev === executable.dev && ino === executable.ino,
        );
      }
    } catch (error) {
      if (error?.code === "ENOENT" || error?.code === "ESRCH") continue;
      // Other users' process facts may be unreadable. The setup lane launches
      // providers as the caller; unreadable caller-owned processes fail closed.
      if (error?.code === "EACCES") {
        const owner = await stat(`/proc/${entry.name}`).catch((cause) => {
          if (cause?.code === "ENOENT") return undefined;
          throw cause;
        });
        if (owner === undefined || owner.uid !== process.getuid()) continue;
      }
      // Finish the inventory so an unrelated restricted process cannot mask a
      // positively identified leak. Unknown caller processes still fail closed.
      inspectionError ??= error;
      continue;
    }
    if (retainedRuntime)
      throw new Error("Clean Linux runner retained a Hopper demo process");
  }
  if (inspectionError !== undefined) throw inspectionError;
};
