document.addEventListener("DOMContentLoaded", function () {
    let safeZoneElement = document.getElementById("safeZoneData");
    if (!safeZoneElement) {
        console.error("Safe zone data not found");
        return;
    }

    let safeZone = JSON.parse(safeZoneElement.textContent);
    let map = null;
    let safeZoneCircle = null;
    let safeZoneMarker = null;
    let userMarker = null;

    window.openLocationModal = function () {
        console.log("Safe Zone Data:", safeZone);

        let userLat = safeZone.user_lat;
        let userLng = safeZone.user_lng;

        if (map === null) {
            initializeMap(safeZone.latitude, safeZone.longitude);
        }
        updateMap(userLat, userLng, safeZone);
        document.getElementById('locationModal').classList.remove('hidden');
    };

    window.closeLocationModal = function () {
        document.getElementById('locationModal').classList.add('hidden');
    };

    function initializeMap(lat, lng) {
        map = L.map("map").setView([lat, lng], 15);

        L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
            maxZoom: 18
        }).addTo(map);
    }

    function updateMap(userLat, userLng, safeZone) {
        let radiusInMeters = safeZone.radius * 1000;
        console.log("Safe Zone Radius (meters):", radiusInMeters);


        // Remove old safe zone circle
        if (safeZoneCircle) {
            map.removeLayer(safeZoneCircle);
        }

        // ✅ Add Safe Zone Circle (More Visible)
        safeZoneCircle = L.circle([safeZone.latitude, safeZone.longitude], {
            color: "blue",
            fillColor: "#1E90FF", // ✅ Darker blue for better visibility
            fillOpacity: 0.6,     // ✅ Increased opacity
            radius: radiusInMeters
        }).addTo(map).bindPopup("Safe Zone Area");

        // Remove old safe zone marker
        if (safeZoneMarker) {
            map.removeLayer(safeZoneMarker);
        }

        // ✅ Add Safe Zone Center Marker (Red)
        safeZoneMarker = L.marker([safeZone.latitude, safeZone.longitude], {
            icon: L.icon({
                iconUrl: "https://maps.gstatic.com/mapfiles/ms2/micons/red-dot.png",
                iconSize: [32, 32],
                iconAnchor: [16, 32]
            })
        }).addTo(map).bindPopup("Safe Zone Center").openPopup();

        // Remove old user marker
        if (userMarker) {
            map.removeLayer(userMarker);
        }

        // ✅ Add User Marker
        userMarker = L.marker([userLat, userLng]).addTo(map)
            .bindPopup("You are here").openPopup();

        // ✅ Adjust Map View with Minimum Zoom
        let bounds = L.latLngBounds([
            [safeZone.latitude, safeZone.longitude],
            [userLat, userLng]
        ]);

        map.fitBounds(bounds, { padding: [50, 50] });

        // ✅ Ensure the map doesn’t zoom too much if locations are close
        let zoomLevel = map.getZoom();
        if (zoomLevel > 15) {
            map.setZoom(15);
        }
    }
});
