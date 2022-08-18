import os
import sys


def banner() -> str:
    sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=32, cols=130))
    banner = r"""
__________                                      __                 ____   ____________  
\______   \___.__.___  _______________    _____/  |_  ___________  \   \ /   /\_____  \ 
 |     ___<   |  |\  \/  /\_  __ \__  \ _/ ___\   __\/  _ \_  __ \  \   Y   /  /  ____/ 
 |    |    \___  | >    <  |  | \// __ \\  \___|  | (  <_> )  | \/   \     /  /       \ 
 |____|    / ____|/__/\_ \ |__|  (____  /\___  >__|  \____/|__|       \___/   \_______ \
           \/           \/            \/     \/                                       \/
"""
    os.system("")
    faded_banner = ""
    blue = 0
    for line in banner.splitlines():
        faded_banner += (f"\033[38;2;0;255;{blue}m{line}\033[0m\n")
        if blue != 255:
            blue += 60
            if blue > 255:
                blue = 255
    faded_banner += fade("\t\t\tMade By github/Rdimo, revived by hissquare")
    return faded_banner


def fade(text: str) -> str:
    os.system("")
    faded = ""
    green = 194
    for line in text:
        faded += (f"\033[38;2;0;{green};199m{line}\033[0m")
        if green != 0:
            green -= 6
            if green < 0:
                green = 0
    return faded
