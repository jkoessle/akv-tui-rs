# VHS documentation
#
# Output:
#   Output <path>.gif               Create a GIF output at the given <path>
#   Output <path>.mp4               Create an MP4 output at the given <path>
#   Output <path>.webm              Create a WebM output at the given <path>
#
# Require:
#   Require <string>                Ensure a program is on the $PATH to proceed
#
# Settings:
#   Set FontSize <number>           Set the font size of the terminal
#   Set FontFamily <string>         Set the font family of the terminal
#   Set Height <number>             Set the height of the terminal
#   Set Width <number>              Set the width of the terminal
#   Set LetterSpacing <float>       Set the font letter spacing (tracking)
#   Set LineHeight <float>          Set the font line height
#   Set LoopOffset <float>%         Set the starting frame offset for the GIF loop
#   Set Theme <json|string>         Set the theme of the terminal
#   Set Padding <number>            Set the padding of the terminal
#   Set Framerate <number>          Set the framerate of the recording
#   Set PlaybackSpeed <float>       Set the playback speed of the recording
#
# Sleep:
#   Sleep <time>                    Sleep for a set amount of <time> in seconds
#
# Type:
#   Type[@<time>] "<string>"        Type a string into the terminal
#
# Keys:
#   Backspace[@<time>] [number]     Press the Backspace key
#   Down[@<time>] [number]          Press the Down key
#   Enter[@<time>] [number]         Press the Enter key
#   Space[@<time>] [number]         Press the Space key
#   Tab[@<time>] [number]           Press the Tab key
#   Left[@<time>] [number]          Press the Left Arrow key
#   Right[@<time>] [number]         Press the Right Arrow key
#   Up[@<time>] [number]            Press the Up Arrow key
#   Down[@<time>] [number]          Press the Down Arrow key
#   PageUp[@<time>] [number]        Press the Page Up key
#   PageDown[@<time>] [number]      Press the Page Down key
#   Ctrl+<key>                      Press the Control key + <key> (e.g. Ctrl+C)
#
# Display:
#   Hide                            Hide the subsequent commands from the output
#   Show                            Show the subsequent commands in the output

Output demo.gif

Set FontSize 16
Set Width 1920
Set Height 1080
Set WindowBar Colorful
Set TypingSpeed 100ms
Set Shell zsh
Set Theme "Dracula"

# Start the application
Type "akv"
Sleep 500ms
Enter
Sleep 2s

Sleep 500ms
Enter

# Wait for secrets to load
Sleep 2s

# Browse the secrets
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 500ms
Up
Sleep 500ms
Up
Sleep 500ms

# Demonstrate Search
Type "/"
Sleep 500ms
Type "secret-n"
Sleep 1s
Enter
Enter
Sleep 2s

# Clear search
Type "/"
Sleep 500ms
Backspace 6
Enter
Sleep 1s

# Demonstrate Adding a Secret
Type "a"
Sleep 1s
Type "demo-secret"
Sleep 1s
Tab
Sleep 500ms
Type "initial-value"
Sleep 1s
Enter
Sleep 2s

# Demonstrate Editing the Secret
# First, find it (it shout be selected, but searching is safer to show flow)
Type "/"
Sleep 500ms
Type "demo-sec"
Sleep 500ms
Enter
Sleep 1s

Type "e"
Sleep 1s
Backspace 13
Type "new-value"
Sleep 500ms
Enter
Sleep 3s

# Demonstrate Copying to Clipboard
Enter
Sleep 1s

# Demonstrate Deleting the Secret
Type "d"
Sleep 1s
Type "y"
Sleep 2s

# Cleanup Search
Type "/"
Sleep 500ms
Backspace 8
Enter
Sleep 1s

# Initial state before exit
Sleep 2s

# Exit
Type "q"
