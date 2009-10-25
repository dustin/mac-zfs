#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

#include <sysexits.h>

int main (int argc, const char * argv[]) {
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	
	NSString *errorDesc = nil;
	NSPropertyListFormat format;
	
	NSString *filePath=@"/System/Library/Filesystems/nofs.fs/Contents/Info.plist";
	if( [[NSFileManager defaultManager] fileExistsAtPath:filePath] )
	{

		NSData *plistXML = [[NSFileManager defaultManager] contentsAtPath:filePath];
	
		NSMutableDictionary *temp = [NSPropertyListSerialization propertyListFromData:plistXML
																 mutabilityOption:NSPropertyListMutableContainersAndLeaves
																		   format:&format
																 errorDescription:&errorDesc];
		if (!temp) {
			NSLog(@"Error reading plist: %@, format: %d", errorDesc, format);
			exit(EX_OSFILE);
		}
	
		NSLog(@"Got list:  %@", temp);
		[[temp objectForKey:@"FSPersonalities"]
				removeObjectForKey:@"ZFS (Not Mountable)"];
		NSLog(@"Mutated to %@", temp);

		NSData *outData = [NSPropertyListSerialization dataFromPropertyList:temp
																 format:format
													   errorDescription:&errorDesc];
	
		if (!outData) {
			NSLog(@"Failed to serialize data.");
			exit(EX_SOFTWARE);
		}
	
		if (![outData writeToFile:filePath atomically:YES]) {
			NSLog(@"Failed to update plist.");
			exit(EX_SOFTWARE);
		}
	}	
	[pool release];
	return 0;
}
