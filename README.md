# Discord Volatility Plugins

## Windows discord_users
Tested on Microsoft Windows [Version 10.0.17763.253]

Plugin to extract discord users from memory.

It will print you the discord ID and the username.

### How does it work ?

You have to give the PID of the process that you want to analyze using --pid or -p.

```
volatility2 -f <path_to_memory_dump> --profile=<profile_name> --plugins=<path_to_plugin_directory> discord_users -p <discord_PID>
```

You need to provide the second discord process.

![Discords](https://github.com/user-attachments/assets/893f8cc0-52ef-475e-bdcb-c45e376ccbe4)

## Android android_discord
Tested on Linux version 4.14.175-g6f3fc9538452.

Plugin to extract conversations from memory.

It will print you the sent message with the author.

You need to provide the discord PID :

```
volatility2 -f <path_to_memory_dump> --profile=<profile_name> --plugins=<path_to_plugin_directory> android_discord -p <discord_PID>
```

# Discord Users Android

### Step 1 - Extract process from memory using linux_dump_map

```
volatility2 -f <path_to_memory_dump> --profile=<profile_name> --plugins=<path_to_plugin_directory> linux_dump_map -p <discord_PID> -D dump/
```

### Step 2 - Obtain all strings from maps

```
strings dump/* > strings.txt
```

### Step 3 - Execute the python script

```
python android_discord_users.py strings.txt
```
