import math

# Function to calculate the Haversine distance
def haversine(lat1, lon1, lat2, lon2):
    # Radius of Earth in kilometers (mean radius)
    R = 6371.0 

    # Convert degrees to radians
    lat1 = math.radians(lat1)
    lon1 = math.radians(lon1)
    lat2 = math.radians(lat2)
    lon2 = math.radians(lon2)

    # Differences in latitude and longitude
    dlat = lat2 - lat1
    dlon = lon2 - lon1

    # Haversine formula
    a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    # Distance in kilometers
    distance = R * c
    return distance

# Function to check if the user is within the safe zone
def is_within_safe_zone(user_lat, user_lon, safe_lat, safe_lon, safe_radius):
    distance = haversine(user_lat, user_lon, safe_lat, safe_lon)
    print(f"Distance to safe zone: {distance:.2f} km")
    
    if distance <= safe_radius:
        print("Access Granted: User is within the safe zone.")
        return True
    else:
        print("Access Denied: User is outside the safe zone.")
        return False

# Example Usage
# User's current location (Latitude, Longitude)
user_lat = 40.730610  # Example: New York City, NY, USA
user_lon = -73.935242

# Safe zone location (Latitude, Longitude)
safe_lat = 40.748817  # Example: Empire State Building, NY, USA
safe_lon = -73.985428

# Safe zone radius in kilometers
safe_radius = 5  # Example: 5 km

# Check if the user is within the safe zone
is_within_safe_zone(user_lat, user_lon, safe_lat, safe_lon, safe_radius)