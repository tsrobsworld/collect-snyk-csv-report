import os
import json
from time import sleep
import typer
import re
from utils.snykApi import get_snyk_export_csv, get_snyk_export_status, initiate_snyk_export_csv

app = typer.Typer()

def validate_datetime_format(value: str):
    datetime_format = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
    if value and not re.match(datetime_format, value):
        raise typer.BadParameter("Date must be in the format YYYY-MM-DDTHH:MM:SSZ")
    return value

def snyk_export_status_check(group_id, export_id, region):
    export_status = get_snyk_export_status(group_id, export_id, region)
    export_report_completed = False
    retry_count = 0
    while not export_report_completed:
        try:
            if export_status['data']['attributes']['status'] == 'FINISHED':
                print(f"Export {export_id} for group {group_id} is finished.  Downloading report url link...")
                return True
            else:
                print(f"Export {export_id} for group {group_id} is not finished.  Retrying in 30 seconds")
                sleep(30)
                retry_count += 1
                export_status = get_snyk_export_status(group_id, export_id, region)
                
        except Exception as e:
            print(f"Error checking export status: {e}.  Retrying in 30 seconds...")
            sleep(30)
            retry_count += 1
        if retry_count > 10:
                    print(f"Error checking export status: {e}.  Exiting...")
                    return False
                
def get_snyk_report(group_id, introduced_from, introduced_to, region):
    snyk_report_response = initiate_snyk_export_csv(group_id, introduced_from, introduced_to, region)
    print(f"Report initiated for {group_id}")
    print(f"Snyk Report Response: {snyk_report_response}")
    export_id = snyk_report_response['data']['id']
    print(f"Export ID: {export_id}")
    report_status = snyk_export_status_check(group_id, export_id, region)
    if report_status:
        report_url = get_snyk_export_csv(group_id, export_id, region)
        print(f"Report URL: {report_url}")
    else:
        print(f"Report {export_id} for group {group_id} is not finished")


@app.command()
def main(
    group_id: str = typer.Option(..., "--group-id", '-g', help="The Snyk group ID to use"),
    introduced_from: str = typer.Option(..., "--introduced-from", '-f', help="The introduced date from to use", callback=validate_datetime_format),
    introduced_to: str = typer.Option(..., "--introduced-to", '-t', help="The introduced date to to use", callback=validate_datetime_format),
    region: str = typer.Option('api.us.snyk.io', "--region", '-r', help="The Snyk region to use.  Default is api.us.snyk.io, other options are api.eu.snyk.io, api.au.snyk.io, api.snyk.io")
):
    get_snyk_report(group_id, introduced_from, introduced_to, region)

if __name__ == "__main__":
    app()