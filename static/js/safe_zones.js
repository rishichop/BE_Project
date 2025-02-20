window.onload = 
function startTracking() {
    if ("geolocation" in navigator) {
        watchID = navigator.geolocation.watchPosition(
            (position) => {
                const latitude = position.coords.latitude;
                const longitude = position.coords.longitude;
                
                document.getElementById('latitude').value = position.coords.latitude;
                document.getElementById('longitude').value = position.coords.longitude;
                console.log(latitude, longitude)
                
                // Send location to the Flask backend
                // fetch('/update_location', {
                //     method: 'POST',
                //     headers: {
                //         'Content-Type': 'application/json'
                //     },
                //     body: JSON.stringify({ latitude: latitude, longitude: longitude })  // Ensure proper JSON format
                // })
                // .then(response => response.json())
                // .then(data => console.log("Server Response:", data))
                // .catch(error => console.error("Error sending location:", error));
            },
            (error) => {
                console.error("Error getting location: ", error);
                startTracking();
            },
            { enableHighAccuracy: true, maximumAge: 0} // High accuracy, update every 5 sec
        );
    } else {
        console.log("Geolocation is not supported by this browser.");
    }
}

function stopTracking() {
    if (watchID) {
        navigator.geolocation.clearWatch(watchID);
        console.log("Stopped tracking.");
    }
}