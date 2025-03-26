from clipshare.security.encrypted_clipboard import EncryptedClipboardListener

def main(): 
    listener = EncryptedClipboardListener()
    listener.start_monitoring()

if __name__ == '__main__':
    main()