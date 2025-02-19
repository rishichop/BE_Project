document.getElementById('loginForm').addEventListener('submit', function(e) {
    e.preventDefault(); // Prevent form from submitting until location is fetched

    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function(position) {
            document.getElementById('latitude').value = position.coords.latitude;
            document.getElementById('longitude').value = position.coords.longitude;
            e.target.submit();

        }, function(error) {
            console.warn('Geolocation error:', error);
                alert('Geolocation failed: ' + error.message);

                // Use Google Geolocation API (IP-based)
                fetch('https://www.googleapis.com/geolocation/v1/geolocate?key=AIzaSyB6Ra2Xxf7BV0-uyTFOdbj_y87G7PSYic0', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ considerIp: true })
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.location) {
                            document.getElementById('latitude').value = data.location.lat;
                            document.getElementById('longitude').value = data.location.lng;
                        } else {
                            console.error('Error: No location data received');
                        }
                        e.target.submit(); // Submit form only after getting IP-based location
                    })
                    .catch(error => {
                        console.error("Error:", error);
                        e.target.submit(); // Fallback: Submit form even if IP lookup fails
                    });

        }, {
            enableHighAccuracy: true, // Force GPS usage
            timeout: 20000, // 10 seconds to get a response
            maximumAge: 0 // No cached location
        });
    } else {
        alert('Geolocation is not supported by this browser.');
        e.target.submit(); // Submit form without coordinates
    }
});
