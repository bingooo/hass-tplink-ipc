import logging

from homeassistant.components.media_player import (
    MediaPlayerEntity,
    MediaPlayerEntityFeature,
    MediaType,
)
from homeassistant.components.media_player.browse_media import (
    async_process_play_media_url,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.const import STATE_IDLE, STATE_PLAYING
from homeassistant.components.media_source import (
    async_browse_media,
    async_resolve_media,
    is_media_source_id,
)
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN
from .models import TPLinkCameraData
from .talkback import TPLinkTalkbackPlayer
from typing import Any
_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the TP-Link IPC Camera media player from a config entry."""
    camera_data: TPLinkCameraData = hass.data[DOMAIN][config_entry.entry_id]
    
    player_entity = TPLinkCameraPlayerEntity(config_entry, camera_data.talkback_client)
    async_add_entities([player_entity])


class TPLinkCameraPlayerEntity(MediaPlayerEntity):
    """Representation of a TP-Link camera as a media player for talkback."""

    _attr_has_entity_name = True

    def __init__(self, config_entry: ConfigEntry, player: TPLinkTalkbackPlayer) -> None:
        """Initialize the media player entity."""
        self._player = player
        self._config_entry = config_entry
        self._attr_name = "Speaker"
        self._attr_state = STATE_IDLE
        self._attr_icon = "mdi:speaker-message"
        self._attr_unique_id = f"{config_entry.unique_id or config_entry.entry_id}_speaker"

        # Link to the same device as the switch
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, config_entry.unique_id or config_entry.entry_id)},
            name=config_entry.title,
        )

        supported_features = (
            MediaPlayerEntityFeature.PLAY_MEDIA
            | MediaPlayerEntityFeature.BROWSE_MEDIA
        )
        if hasattr(MediaPlayerEntityFeature, "ANNOUNCE"):
            supported_features |= MediaPlayerEntityFeature.ANNOUNCE
        self._attr_supported_features = supported_features

    @property
    def media_content_type(self) -> str:
        """Content type of current playing media."""
        return MediaType.MUSIC

    async def async_play_media(self, media_type: str, media_id: str, **kwargs: Any) -> None:
        """Play media from a URL or media_source URI."""
        _LOGGER.info(f"Received play request. Type: {media_type}, Original ID: {media_id}")

        media_url = None
        if is_media_source_id(media_id):
            try:
                resolved_media = await async_resolve_media(self.hass, media_id, self.entity_id)
                media_url = resolved_media.url
                _LOGGER.info(f"Resolved media ID to playable URL: {media_url}")
            except HomeAssistantError as err:
                _LOGGER.error(f"Failed to resolve media source: {err}")
                return
        else:
            media_url = media_id
            _LOGGER.info(f"Received direct media path: {media_url}")

        if not media_url:
            _LOGGER.error("Could not determine a valid media URL.")
            return

        if media_url.startswith("/"):
            absolute_url = async_process_play_media_url(self.hass, media_url)
            _LOGGER.info(f"Converted relative path to absolute URL: {absolute_url}")
        else:
            absolute_url = media_url

        self._attr_state = STATE_PLAYING
        self.async_write_ha_state()

        await self.hass.async_add_executor_job(self._play_media_blocking, absolute_url)

    def _play_media_blocking(self, media_url: str) -> None:
        """Blocking method that runs in a separate thread."""
        try:
            self._player.play_media(media_url)
        except Exception as e:
            _LOGGER.error(f"Error playing media on camera: {e}")
        finally:
            self.hass.add_job(self.async_set_idle)

    async def async_set_idle(self) -> None:
        """Set the state to idle and update Home Assistant."""
        self._attr_state = STATE_IDLE
        self.async_write_ha_state()

    async def async_browse_media(self, media_content_type=None, media_content_id=None):
        """Implement the media browser."""
        return await async_browse_media(self.hass, media_content_id)