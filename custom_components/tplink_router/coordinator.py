from __future__ import annotations
import hashlib
from datetime import timedelta, datetime
from logging import Logger
from collections.abc import Callable
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.exceptions import HomeAssistantError
from tplinkrouterc6u import (
    TplinkRouterProvider,
    AbstractRouter,
    Firmware,
    Status,
    Connection,
    LTEStatus,
    SMS,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, DeviceInfo
from .const import (
    DOMAIN,
    DEFAULT_NAME,
)


class TPLinkRouterCoordinator(DataUpdateCoordinator):
    def __init__(
            self,
            hass: HomeAssistant,
            router: AbstractRouter,
            update_interval: int,
            firmware: Firmware,
            status: Status,
            lte_status: LTEStatus | None,
            logger: Logger,
            unique_id: str
    ) -> None:
        self.router = router
        self.unique_id = unique_id
        self.status = status
        self.tracked = {}
        self.lte_status = lte_status
        self._wifi_write_supported: dict[Connection, bool] = {}
        self.device_info = DeviceInfo(
            configuration_url=router.host,
            connections={(CONNECTION_NETWORK_MAC, self.status.lan_macaddr)},
            identifiers={(DOMAIN, self.status.lan_macaddr)},
            manufacturer="TPLink",
            model=firmware.model,
            name=DEFAULT_NAME,
            sw_version=firmware.firmware_version,
            hw_version=firmware.hardware_version,
        )

        self.scan_stopped_at: datetime | None = None
        self._last_update_time: datetime | None = None
        self._sms_hashes: set[str] = set()
        self.new_sms: list[SMS] = []

        super().__init__(
            hass,
            logger,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval),
        )

    @staticmethod
    async def get_client(hass: HomeAssistant, host: str, password: str, username: str, logger: Logger,
                         verify_ssl: bool) -> AbstractRouter:
        return await hass.async_add_executor_job(TplinkRouterProvider.get_client, host, password, username,
                                                 logger, verify_ssl)

    @staticmethod
    def request(router: AbstractRouter, callback: Callable):
        router.authorize()
        try:
            return callback()
        finally:
            try:
                router.logout()
            except Exception:
                # Do not block updates if logout fails.
                pass

    async def reboot(self) -> None:
        await self.hass.async_add_executor_job(TPLinkRouterCoordinator.request, self.router, self.router.reboot)

    async def set_wifi(self, wifi: Connection, enable: bool) -> None:
        def callback():
            self.router.set_wifi(wifi, enable)
            return self.router.get_status()

        try:
            self.status = await self.hass.async_add_executor_job(
                TPLinkRouterCoordinator.request,
                self.router,
                callback,
            )
            self._wifi_write_supported[wifi] = True
            self.async_set_updated_data(self.status)
        except Exception as err:
            if TPLinkRouterCoordinator._is_deco_app_only_write_error(err):
                for conn in TPLinkRouterCoordinator._expand_related_connections(wifi):
                    self._wifi_write_supported[conn] = False
                self.async_set_updated_data(self.status)
                raise HomeAssistantError(
                    "This Deco firmware does not allow changing this Wi-Fi setting via local web API. "
                    "Use the Deco app for this action."
                ) from err
            raise

    def is_wifi_writable(self, wifi: Connection) -> bool:
        return self._wifi_write_supported.get(wifi, True)

    @staticmethod
    def _expand_related_connections(wifi: Connection) -> list[Connection]:
        if wifi in [Connection.GUEST_2G, Connection.GUEST_5G, Connection.GUEST_6G]:
            return [Connection.GUEST_2G, Connection.GUEST_5G, Connection.GUEST_6G]
        if wifi in [Connection.HOST_2G, Connection.HOST_5G, Connection.HOST_6G]:
            return [Connection.HOST_2G, Connection.HOST_5G, Connection.HOST_6G]
        if wifi in [Connection.IOT_2G, Connection.IOT_5G, Connection.IOT_6G]:
            return [Connection.IOT_2G, Connection.IOT_5G, Connection.IOT_6G]
        return [wifi]

    @staticmethod
    def _is_deco_app_only_write_error(err: Exception) -> bool:
        text = str(err)
        return "WLAN write was sent but no state change was observed" in text

    async def _async_update_data(self):
        """Asynchronous update of all data."""
        if self.scan_stopped_at is not None and self.scan_stopped_at > (datetime.now() - timedelta(minutes=20)):
            return
        self.scan_stopped_at = None
        self.status = await self.hass.async_add_executor_job(TPLinkRouterCoordinator.request, self.router,
                                                             self.router.get_status)
        # Only fetch if router is lte_status compatible
        if self.lte_status is not None:
            self.lte_status = await self.hass.async_add_executor_job(
                TPLinkRouterCoordinator.request,
                self.router,
                self.router.get_lte_status,
            )
        await self._update_new_sms()
        self._last_update_time = datetime.now()

    async def _update_new_sms(self) -> None:
        if not hasattr(self.router, "get_sms") or self.lte_status is None:
            return
        sms_list = await self.hass.async_add_executor_job(TPLinkRouterCoordinator.request, self.router,
                                                          self.router.get_sms)
        new_items = []
        for sms in sms_list:
            h = TPLinkRouterCoordinator._hash_item(sms)
            if self._last_update_time is None:
                self._sms_hashes.add(h)
            elif h not in self._sms_hashes:
                self._sms_hashes.add(h)
                new_items.append(sms)

        self.new_sms = new_items

    @staticmethod
    def _hash_item(sms: SMS) -> str:
        key = f"{sms.sender}|{sms.content}|{sms.received_at.isoformat()}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()
