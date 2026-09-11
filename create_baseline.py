import sqlite3

from database.database import (
    initialize_database,
    save_baseline_port,
)


DB_NAME = "data/homesoc.db"


def create_baseline():

    initialize_database()

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    # Only baseline services currently known to be OPEN.
    #
    # Join through devices so we can associate the
    # current IP address with its MAC identity.

    cursor.execute("""
        SELECT
            d.mac,
            s.ip,
            s.port,
            s.protocol
        FROM services s

        JOIN devices d
            ON s.ip = d.ip

        WHERE
            s.state = 'OPEN'
            AND d.mac IS NOT NULL
    """)

    rows = cursor.fetchall()

    connection.close()

    print()
    print("HomeSOC Service Baseline")
    print("------------------------")

    count = 0

    for (
        mac,
        ip,
        port,
        protocol,
    ) in rows:

        save_baseline_port(
            mac=mac,
            port=port,
            protocol=protocol,
        )

        print(
            f"Baseline: "
            f"{ip} | "
            f"{mac} | "
            f"{port}/{protocol}"
        )

        count += 1

    print()
    print(
        f"Baseline created with "
        f"{count} expected services."
    )


if __name__ == "__main__":
    create_baseline()