import asyncio
from winrt.windows.devices.wifidirect import WiFiDirectAdvertisementPublisher
from winrt.windows.networking.sockets import StreamSocketListener, SocketProtectionLevel
from winrt.windows.storage.streams import DataReader

async def start_wifi_direct_host():
    # Pornește publisherul Wi-Fi Direct
    publisher = WiFiDirectAdvertisementPublisher()
    publisher.advertisement.is_autonomous_group_owner_enabled = True
    publisher.start()
    print("[HOST] Wi-Fi Direct publisher started.")

    # Ascultă conexiuni pe portul 1337
    listener = StreamSocketListener()
    await listener.bind_service_name_async("1337")
    print("[HOST] Listening for incoming connections...")

    async def handle_connection(args):
        print("[HOST] Connection received.")
        reader = DataReader(args.socket.input_stream)
        reader.unicode_encoding = 0  # UTF8
        await reader.load_async(1024)
        filename = reader.read_string(reader.unconsumed_buffer_length)
        print(f"[HOST] Receiving file: {filename}")

        # Poți extinde aici cu logica de salvare a fișierului

    def on_connection_received(sender, args):
        asyncio.create_task(handle_connection(args))

    listener.connection_received += on_connection_received
    await asyncio.sleep(300)  # rulează 5 minute

if __name__ == "__main__":
    asyncio.run(start_wifi_direct_host())
