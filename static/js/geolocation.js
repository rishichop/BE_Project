document.getElementById('loginForm').addEventListener('submit', function(e) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function(position) {
            document.getElementById('latitude').value = position.coords.latitude;
            document.getElementById('longitude').value = position.coords.longitude;
            e.target.submit();
        }, function(error) {
            console.warn('Geolocation error:', error);
            // Submit without coordinates (server will use IP)
            e.target.submit();
        });
    } else {
        e.target.submit();
    }
});