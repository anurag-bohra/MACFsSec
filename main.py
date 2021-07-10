import sys
from watchdog.observers import Observer
from watchdog.events import RegexMatchingEventHandler, FileSystemEventHandler
import os
import threading
import utilities
import time
import utilities

MAIN_OBSERVER_OBJECT = None
INACTIVE_MONITOR_PATHS = list()
ACTIVE_MONITOR_PATHS_WATCH = list()


class ExtHandler(RegexMatchingEventHandler):
    def on_created(self, event):
        utilities.event_handler(event)

    def on_modified(self, event):
        utilities.event_handler(event)

    def on_moved(self, event):
        utilities.event_handler(event)


class magicHandler(FileSystemEventHandler):
    def check_magic(self, path):
        if os.path.exists(path):
            return utilities.check_macho(path)

    def on_created(self, event):
        if self.check_magic(event.src_path):
            utilities.event_handler(event)

    def on_moved(self, event):
        if self.check_magic(event.src_path):
            utilities.event_handler(event)

    def on_modified(self, event):
        if self.check_magic(event.src_path):
            utilities.event_handler(event)


def update_watchdog():
    global MAIN_OBSERVER_OBJECT
    global ACTIVE_MONITOR_PATHS_WATCH
    if MAIN_OBSERVER_OBJECT is not None:
        global INACTIVE_MONITOR_PATHS
        regexes = list()
        regexes.append(utilities.form_regex())
        handler = ExtHandler(regexes=regexes, ignore_directories=True, case_sensitive=False)
        magic_handler = magicHandler()
        while (True):
            for path in INACTIVE_MONITOR_PATHS:
                if os.path.exists(path):
                    watch = MAIN_OBSERVER_OBJECT.schedule(handler, path=path, recursive=True)
                    MAIN_OBSERVER_OBJECT.add_handler_for_watch(magic_handler, watch)
                    INACTIVE_MONITOR_PATHS.remove(path)
                    temp = dict()
                    temp['path'] = path
                    temp['object'] = watch
                    ACTIVE_MONITOR_PATHS_WATCH.append(temp)
            for pathObject in ACTIVE_MONITOR_PATHS_WATCH:
                path = pathObject['path']
                if not os.path.exists(path):
                    removeWatch = MAIN_OBSERVER_OBJECT.unschedule(pathObject['object'])
                    ACTIVE_MONITOR_PATHS_WATCH.remove(pathObject)
                    INACTIVE_MONITOR_PATHS.append(path)


def init_watchdog(paths):
    global MAIN_OBSERVER_OBJECT
    global ACTIVE_MONITOR_PATHS_WATCH
    regexes = list()
    regexes.append(utilities.form_regex())
    handler = ExtHandler(regexes=regexes, ignore_directories=True, case_sensitive=False)
    magic_handler = magicHandler()
    observer = Observer()
    MAIN_OBSERVER_OBJECT = observer
    for path in paths:
        watch = observer.schedule(handler, path=path, recursive=True)
        observer.add_handler_for_watch(magic_handler, watch)
        temp = dict()
        temp['path'] = path
        temp['object'] = watch
        ACTIVE_MONITOR_PATHS_WATCH.append(temp)
    try:
        observer.start()
    except FileNotFoundError:
        print("ERROR")
        sys.exit(1)
    try:
        while True:
            # Set the thread sleep time
            time.sleep(1)
    except KeyboardInterrupt:
        print("ERROR")
        observer.stop()
    observer.join()


def main():
    settings = utilities.read_yaml()
    global INACTIVE_MONITOR_PATHS
    paths = settings['paths']
    complete_paths = list()
    if paths is None:
        complete_paths.append('/')
    else:
        total_paths = [os.path.expanduser(path) for path in paths]
        complete_paths = [path for path in total_paths if os.path.exists(path)]
        INACTIVE_MONITOR_PATHS = [path for path in total_paths if path not in complete_paths]
    mainWatchdogThread = threading.Thread(target=init_watchdog, name='main Watchdog Thread', args=(complete_paths,))
    mainWatchdogThread.start()
    time.sleep(5)
    updateWatchdogThread = threading.Thread(target=update_watchdog, name='Update Watchdog Thread')
    updateWatchdogThread.start()



if __name__ == "__main__":
    main()