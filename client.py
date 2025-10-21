import asyncio
from winrt.windows.devices.enumeration import DeviceInformation, DeviceClass
from winrt.windows.devices.wifidirect import WiFiDirectDevice
from winrt.windows.networking.sockets import StreamSocket
from winrt.windows.storage.streams import DataWriter

async def connect_and_send_file():
    print("[CLIENT] Searching for Wi-Fi Direct devices...")
    devices = await DeviceInformation.find_all_async(DeviceClass.all)

    target_device = None
    for device in devices:
        if "Wi-Fi Direct" in device.name:
            print(f"[CLIENT] Found device: {device.name}")
            target_device = device
            break

    if not target_device:
        print("[CLIENT] No Wi-Fi Direct device found.")
        return

    wfd_device = await WiFiDirectDevice.from_id_async(target_device.id)
    endpoint = wfd_device.connection_endpoint

    socket = StreamSocket()
    await socket.connect_async(endpoint, "1337")
    print("[CLIENT] Connected to host.")

    writer = DataWriter(socket.output_stream)
    writer.unicode_encoding = 0  # UTF8
    filename = "test_file.txt"
    writer.write_string(filename)
    await writer.store_async()
    await writer.flush_async()
    print(f"[CLIENT] Sent filename: {filename}")

    # Poți extinde aici cu logica de trimitere a conținutului fișierului

if __name__ == "__main__":
    asyncio.run(connect_and_send_file())
