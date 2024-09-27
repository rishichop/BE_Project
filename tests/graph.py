import matplotlib.pyplot as plt
from matplotlib.patches import Circle
import cartopy.crs as ccrs
import math

# Haversine formula to calculate distance
def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0  # Radius of the Earth in km
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

# User location and safe zone
user_lat = 40.730610  # New York City
user_lon = -73.935242
safe_lat = 40.748817  # Empire State Building
safe_lon = -73.985428
safe_radius = 5  # 5 km radius

# Check if user is within the safe zone
distance = haversine(user_lat, user_lon, safe_lat, safe_lon)
print(f"Distance between user and safe zone: {distance:.2f} km")
is_safe = distance <= safe_radius
print(f"Is user within safe zone? {'Yes' if is_safe else 'No'}")

# Function to convert radius (in km) to degrees
def radius_to_degrees(radius_km, latitude):
    # Convert the radius from km to degrees
    # 1 degree latitude is approximately 111.32 km, longitude varies with latitude
    lat_degree = radius_km / 111.32
    lon_degree = radius_km / (111.32 * math.cos(math.radians(latitude)))
    return lat_degree, lon_degree

# Plotting the map and safe zone
def plot_safe_zone(user_lat, user_lon, safe_lat, safe_lon, safe_radius):
    # Convert the safe zone radius to degrees
    lat_radius, lon_radius = radius_to_degrees(safe_radius, safe_lat)

    # Create a plot with a map projection
    fig = plt.figure(figsize=(10, 7))
    ax = plt.axes(projection=ccrs.PlateCarree())
    ax.stock_img()

    # Plot user's location
    plt.plot(user_lon, user_lat, 'ro', markersize=10, label='User Location')
    
    # Plot safe zone center
    plt.plot(safe_lon, safe_lat, 'bo', markersize=10, label='Safe Zone Center')
    
    # Draw a circular safe zone by calculating the latitude and longitude boundary
    circle = plt.Circle((safe_lon, safe_lat), lon_radius, color='blue', fill=True, alpha=0.2,
                        transform=ccrs.PlateCarree(), label='Safe Zone')
    ax.add_patch(circle)

    # Add labels
    plt.text(user_lon + 0.01, user_lat + 0.01, 'User', fontsize=12, color='red', transform=ccrs.PlateCarree())
    plt.text(safe_lon + 0.01, safe_lat + 0.01, 'Safe Zone', fontsize=12, color='blue', transform=ccrs.PlateCarree())

    # Add legend
    plt.legend(loc='lower left')

    # Set map extent to focus on the area
    ax.set_extent([-74.1, -73.7, 40.5, 40.9], crs=ccrs.PlateCarree())

    # Show the plot
    plt.title('User Location and Safe Zone')
    plt.show()

# Call the plot function
plot_safe_zone(user_lat, user_lon, safe_lat, safe_lon, safe_radius)
