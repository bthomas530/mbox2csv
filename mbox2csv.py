#!/usr/bin/env python3
"""
Extract email addresses, names, and company information from an mbox file and save them to a CSV file.
"""

import mailbox
import re
import csv
import argparse
from collections import defaultdict
from email.utils import parseaddr, getaddresses
import os
import email

def extract_info_from_mbox(mbox_file):
    """
    Extract email addresses, names, and company information from an mbox file.
    Returns a dictionary with email addresses as keys and contact information as values.
    """
    email_pattern = r'[\w.+-]+@[\w-]+\.[\w.-]+'
    # Common signature indicators
    signature_patterns = [
        r'(?i)^\s*--+\s*$',  # Dashed line
        r'(?i)^\s*regards\s*,?$',
        r'(?i)^\s*sincerely\s*,?$',
        r'(?i)^\s*best\s*,?$',
        r'(?i)^\s*thank\s*you\s*,?$',
        r'(?i)^\s*cheers\s*,?$'
    ]
    
    # Dictionary to store contact information
    contacts = {}
    
    # Open the mbox file
    mbox = mailbox.mbox(mbox_file)
    
    # Process each message in the mbox file
    for message in mbox:
        # Extract email and name from From header
        from_header = message.get('from', '')
        if from_header:
            name, email_addr = parseaddr(from_header)
            email_addr = email_addr.lower() if email_addr else ''
            
            if email_addr and re.match(email_pattern, email_addr):
                # Initialize contact info if this is a new email
                if email_addr not in contacts:
                    # Extract domain as potential company name
                    domain = email_addr.split('@')[-1] if '@' in email_addr else ''
                    company = domain.split('.')[0] if domain else ''
                    
                    # Clean up company name (capitalize words, remove hyphens)
                    if company and company not in ('gmail', 'yahoo', 'hotmail', 'outlook', 'icloud', 'aol', 'protonmail'):
                        company = ' '.join(word.capitalize() for word in re.split(r'[-_]', company))
                    else:
                        company = ''
                    
                    contacts[email_addr] = {
                        'name': name.strip() if name else '',
                        'company': company,
                        'seen_in_headers': set()
                    }
                
                # Update name if it's empty and we have a new one
                if not contacts[email_addr]['name'] and name:
                    contacts[email_addr]['name'] = name.strip()
                
                # Add this header to seen headers
                contacts[email_addr]['seen_in_headers'].add('from')
        
        # Check other headers for additional emails
        for header in ['to', 'cc', 'reply-to']:
            if header in message:
                # Get all addresses from the header
                addresses = getaddresses([message[header]])
                for name, email_addr in addresses:
                    email_addr = email_addr.lower() if email_addr else ''
                    if email_addr and re.match(email_pattern, email_addr):
                        if email_addr not in contacts:
                            # Extract domain as potential company name
                            domain = email_addr.split('@')[-1] if '@' in email_addr else ''
                            company = domain.split('.')[0] if domain else ''
                            
                            # Clean up company name
                            if company and company not in ('gmail', 'yahoo', 'hotmail', 'outlook', 'icloud', 'aol', 'protonmail'):
                                company = ' '.join(word.capitalize() for word in re.split(r'[-_]', company))
                            else:
                                company = ''
                                
                            contacts[email_addr] = {
                                'name': name.strip() if name else '',
                                'company': company,
                                'seen_in_headers': set()
                            }
                        
                        # Update name if it's empty and we have a new one
                        if not contacts[email_addr]['name'] and name:
                            contacts[email_addr]['name'] = name.strip()
                        
                        # Add this header to seen headers
                        contacts[email_addr]['seen_in_headers'].add(header)
        
        # Try to extract company information from signature in plain text messages
        if message.get_content_type() == 'text/plain':
            try:
                body = message.get_payload(decode=True).decode('utf-8', errors='ignore')
                
                # Split into lines
                lines = body.split('\n')
                
                # Look for signature indicators
                in_signature = False
                signature_lines = []
                
                for line in lines:
                    # Check if this line indicates the start of a signature
                    if not in_signature:
                        for pattern in signature_patterns:
                            if re.match(pattern, line):
                                in_signature = True
                                break
                    
                    if in_signature:
                        signature_lines.append(line.strip())
                
                # Process signature lines for company information
                if signature_lines:
                    # Extract emails from signature
                    sig_emails = set()
                    for line in signature_lines:
                        found_emails = re.findall(email_pattern, line)
                        sig_emails.update([e.lower() for e in found_emails])
                    
                    # Look for potential company names in signature
                    # Common patterns: "at Company", "Company, Inc.", "Company Ltd"
                    company_patterns = [
                        r'(?i)at\s+([A-Z][A-Za-z0-9\s&\.,]+?)(?:\s*[,\.;]|$)',
                        r'(?i)([A-Z][A-Za-z0-9\s&]+?)\s*,?\s*(?:Inc|LLC|Ltd|Limited|Corp|Corporation|Co)\b',
                        r'(?i)([A-Z][A-Za-z0-9\s&]+?)\s*[|]\s*',
                    ]
                    
                    potential_company = None
                    for line in signature_lines:
                        for pattern in company_patterns:
                            match = re.search(pattern, line)
                            if match:
                                potential_company = match.group(1).strip()
                                break
                        if potential_company:
                            break
                    
                    # Update company info for emails found in signature
                    for email_addr in sig_emails:
                        if email_addr in contacts and potential_company:
                            if not contacts[email_addr]['company']:
                                contacts[email_addr]['company'] = potential_company
                
                # Also look for emails in the body
                body_emails = re.findall(email_pattern, body)
                for email_addr in body_emails:
                    email_addr = email_addr.lower()
                    if email_addr not in contacts:
                        # Extract domain as potential company name
                        domain = email_addr.split('@')[-1] if '@' in email_addr else ''
                        company = domain.split('.')[0] if domain else ''
                        
                        # Clean up company name
                        if company and company not in ('gmail', 'yahoo', 'hotmail', 'outlook', 'icloud', 'aol', 'protonmail'):
                            company = ' '.join(word.capitalize() for word in re.split(r'[-_]', company))
                        else:
                            company = ''
                            
                        contacts[email_addr] = {
                            'name': '',
                            'company': company,
                            'seen_in_headers': set()
                        }
                
            except Exception as e:
                print(f"Error processing message body: {e}")
    
    # Clean up the contacts dictionary before returning
    for email_addr in contacts:
        # Convert seen_in_headers set to a string for easier CSV output
        contacts[email_addr]['seen_in_headers'] = ', '.join(contacts[email_addr]['seen_in_headers'])
    
    return contacts

def save_to_csv(contacts, output_file):
    """
    Save contact information to a CSV file.
    """
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Email', 'Name', 'Company', 'Seen In Headers']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        # Sort by email address
        for email in sorted(contacts.keys()):
            writer.writerow({
                'Email': email,
                'Name': contacts[email]['name'],
                'Company': contacts[email]['company'],
                'Seen In Headers': contacts[email]['seen_in_headers']
            })
    
    print(f"Extracted {len(contacts)} unique contacts to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Extract contact information from an mbox file to CSV')
    parser.add_argument('--mbox', default='topics.mbox', help='Path to the mbox file (default: topics.mbox)')
    parser.add_argument('--output', default='contacts.csv', help='Output CSV file (default: contacts.csv)')
    args = parser.parse_args()
    
    if not os.path.exists(args.mbox):
        print(f"Error: Mbox file '{args.mbox}' not found.")
        return
    
    print(f"Processing mbox file: {args.mbox}")
    contacts = extract_info_from_mbox(args.mbox)
    save_to_csv(contacts, args.output)

if __name__ == "__main__":
    main()
