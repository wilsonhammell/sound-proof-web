from soundproof import launch_website

#this app is launched by gunicorn with given number of workers and threads from startup.txt
app = launch_website()
