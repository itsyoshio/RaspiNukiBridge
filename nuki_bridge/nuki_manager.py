import asyncio
from bleak import BleakScanner
from bleak.exc import BleakDBusError
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from pyNukiBT import NukiDevice, NukiConst

from utils import logger

class NukiManager:
    def __init__(self, name, app_id):
        self.name = name
        self.app_id = app_id
        self.type_id = NukiConst.NukiClientType.BRIDGE
        self._newstate_callback = None

        self._devices = {}
        self._scanner = BleakScanner(detection_callback=self._detected_ibeacon)

    @property
    def newstate_callback(self):
        return self._newstate_callback

    @newstate_callback.setter
    def newstate_callback(self, value):
        self._newstate_callback = value
        for device in self._devices.values():
            asyncio.get_event_loop().create_task(self.newstate_callback(device))

    async def nuki_newstate(self, nuki):
        if self.newstate_callback:
            await self.newstate_callback(nuki)

    def __getitem__(self, index):
        return list(self._devices.values())[index]

    def nuki_by_id(self, nuki_id) -> NukiDevice:
        #todo: will fail if no config yet.
        return next(nuki for nuki in self._devices.values() if nuki.config.get("nuki_id") == nuki_id)

    def add_nuki(self, nuki: NukiDevice):
        self._devices[nuki._address] = nuki

    @property
    def device_list(self):
        return list(self._devices.values())

    def start(self, loop=None):
        pass

    async def start_scanning(self):
        ATTEMPTS = 8
        logger.info(f"Starting a scan")
        for i in range(1, ATTEMPTS + 1):
            try:
                logger.info(f"Scanning attempt {i}")
                await self._scanner.start()
                logger.info(f"Scanning succeeded on attempt {i}")
                break
            except BleakDBusError as ex:
                logger.error(f"Error while start scanning attempt {i}")
                logger.exception(ex)
                if i >= ATTEMPTS - 1:
                    raise ex
                sleep_seconds = 2
                logger.info(f"Scanning failed on attempt {i}. Retrying in {sleep_seconds} seconds")
                asyncio.sleep(sleep_seconds)

    async def stop_scanning(self, timeout=10.0):
        logger.info("Stop scanning")
        try:
            await asyncio.wait_for(self._scanner.stop(), timeout=timeout)
            logger.info("Scanning stopped")
        except (TimeoutError, asyncio.CancelledError) as e:
            logger.error(f'Timeout while stop scanning')
            logger.exception(e)
        except AttributeError as e:
            logger.error('Error while stop scanning. Scan was probably not started.')
            logger.exception(e)
        except Exception as e:
            logger.error('Error while stop scanning')
            logger.exception(e)

    async def _detected_ibeacon(self, device: BLEDevice, advertisement_data: AdvertisementData):
        if device.address in self._devices:
            nuki = self._devices[device.address]
            nuki.parse_advertisement_data(device, advertisement_data)
            if nuki.poll_needed():
                await nuki.update_state()
