from google.oauth2 import service_account
from google.cloud import compute_v1, storage, container_v1
from google.api_core.exceptions import GoogleAPIError
import mysql.connector

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'network_scanner'
}


def get_gcp_resources(project_id, credentials_path):
    result = {
        "vms": [],
        "buckets": [],
        "gke_clusters": [],
        "error": None
    }

    try:
        credentials = service_account.Credentials.from_service_account_file(credentials_path)

        instance_client = compute_v1.InstancesClient(credentials=credentials)
        zones_client = compute_v1.ZonesClient(credentials=credentials)

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS gcp_vms (
                name VARCHAR(100) PRIMARY KEY,
                zone VARCHAR(50),
                status VARCHAR(50),
                machine_type VARCHAR(100),
                scan_id INT,
                FOREIGN KEY (scan_id) REFERENCES cloud_scan_history(id) ON DELETE SET NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS gcp_buckets (
                name VARCHAR(100) PRIMARY KEY,
                location VARCHAR(50),
                storage_class VARCHAR(50),
                scan_id INT,
                FOREIGN KEY (scan_id) REFERENCES cloud_scan_history(id) ON DELETE SET NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS gcp_gke_clusters (
                name VARCHAR(100) PRIMARY KEY,
                location VARCHAR(50),
                status VARCHAR(50),
                endpoint VARCHAR(100),
                scan_id INT,
                FOREIGN KEY (scan_id) REFERENCES cloud_scan_history(id) ON DELETE SET NULL
            )
        ''')

        cursor.execute("INSERT INTO cloud_scan_history (provider) VALUES ('gcp')")
        scan_id = cursor.lastrowid

        zones = [zone.name for zone in zones_client.list(project=project_id)]
        for zone in zones:
            try:
                vms = instance_client.list(project=project_id, zone=zone)
                for vm in vms:
                    name = vm.name
                    status = vm.status
                    machine_type = vm.machine_type.split("/")[-1] if vm.machine_type else "N/A"

                    result['vms'].append({
                        "name": name,
                        "zone": zone,
                        "status": status,
                        "machine_type": machine_type
                    })

                    cursor.execute('''
                        INSERT INTO gcp_vms (name, zone, status, machine_type, scan_id)
                        VALUES (%s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                            zone=VALUES(zone),
                            status=VALUES(status),
                            machine_type=VALUES(machine_type),
                            scan_id=VALUES(scan_id)
                    ''', (name, zone, status, machine_type, scan_id))

            except GoogleAPIError:
                continue

        # Buckets
        storage_client = storage.Client(project=project_id, credentials=credentials)
        for bucket in storage_client.list_buckets():
            result['buckets'].append({
                "name": bucket.name,
                "location": bucket.location,
                "storage_class": bucket.storage_class
            })

            cursor.execute('''
                INSERT INTO gcp_buckets (name, location, storage_class, scan_id)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    location=VALUES(location),
                    storage_class=VALUES(storage_class),
                    scan_id=VALUES(scan_id)
            ''', (bucket.name, bucket.location, bucket.storage_class, scan_id))

        # GKE Clusters
        container_client = container_v1.ClusterManagerClient(credentials=credentials)
        locations = container_client.list_locations(parent=f"projects/{project_id}").locations

        for location in locations:
            try:
                resp = container_client.list_clusters(parent=f"projects/{project_id}/locations/{location.location_id}")
                for cluster in resp.clusters:
                    result['gke_clusters'].append({
                        "name": cluster.name,
                        "location": location.location_id,
                        "status": cluster.status.name,
                        "endpoint": cluster.endpoint
                    })

                    cursor.execute('''
                        INSERT INTO gcp_gke_clusters (name, location, status, endpoint, scan_id)
                        VALUES (%s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                            location=VALUES(location),
                            status=VALUES(status),
                            endpoint=VALUES(endpoint),
                            scan_id=VALUES(scan_id)
                    ''', (cluster.name, location.location_id, cluster.status.name, cluster.endpoint, scan_id))
            except GoogleAPIError:
                continue

        conn.commit()

    except Exception as e:
        result["error"] = str(e)

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return result
