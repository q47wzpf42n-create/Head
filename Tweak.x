#import <UIKit/UIKit.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdatomic.h>
#include <string.h>
#include <stdint.h>

// ─── Patch target ─────────────────────────────────────────────────────────────
//  0x626F6479 = "body"
//  0x68656164 = "head"
static const uint8_t kFind[]    = { 0x62, 0x6F, 0x64, 0x79 };
static const uint8_t kReplace[] = { 0x68, 0x65, 0x61, 0x64 };
static const size_t  kPatLen    = 4;

// ─── Swipe config ─────────────────────────────────────────────────────────────
static const CGFloat kSwipeThreshold = 5.0f; // px, upward only

// ─── State ────────────────────────────────────────────────────────────────────
// All UIKit event callbacks are main-thread; patch dispatch goes background.
// gPatchDone written once from main thread before dispatch — atomic for
// visibility across threads.
static atomic_bool  gPatchDone  = ATOMIC_VAR_INIT(false);
static BOOL         gTracking   = NO;   // main-thread only
static CGFloat      gStartY     = 0.0f; // main-thread only

// ─── Mach vm_protect helper ───────────────────────────────────────────────────
static kern_return_t
setProt(void *addr, size_t len, vm_prot_t prot) {
    vm_address_t base = (vm_address_t)addr & ~(vm_address_t)(vm_page_size - 1);
    vm_size_t    size = len + ((vm_address_t)addr - base);
    return vm_protect(mach_task_self(), base, size, FALSE, prot);
}

// ─── Segment classification ───────────────────────────────────────────────────
typedef enum {
    kSegSkip = 0,
    kSegText,
    kSegData,
} SegKind;

static SegKind classifySeg(const char *name) {
    if (strcmp(name, "__PAGEZERO") == 0) return kSegSkip;  // no valid VA
    if (strcmp(name, "__LINKEDIT") == 0) return kSegSkip;  // raw file data
    if (strcmp(name, "__TEXT")     == 0) return kSegText;
    // __DATA, __DATA_CONST, __DATA_DIRTY, __AUTH, __AUTH_CONST …
    if (strncmp(name, "__DATA", 6)  == 0) return kSegData;
    if (strncmp(name, "__AUTH", 6)  == 0) return kSegData;
    // Any other segment: attempt scan as data-like
    return kSegData;
}

// ─── Core scanner/patcher ─────────────────────────────────────────────────────
static uint32_t
scanAndPatch(void) {
    uint32_t hits = 0;
    uint32_t nimgs = _dyld_image_count();

    for (uint32_t imgIdx = 0; imgIdx < nimgs; imgIdx++) {

        const struct mach_header *mhRaw = _dyld_get_image_header(imgIdx);
        if (!mhRaw || mhRaw->magic != MH_MAGIC_64) continue;

        const struct mach_header_64 *mh = (const struct mach_header_64 *)mhRaw;
        intptr_t slide = _dyld_get_image_vmaddr_slide(imgIdx);

        const uint8_t *lc = (const uint8_t *)(mh + 1);

        for (uint32_t ci = 0; ci < mh->ncmds; ci++) {
            const struct load_command *cmd = (const struct load_command *)lc;

            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)cmd;

                SegKind kind = classifySeg(seg->segname);
                if (kind == kSegSkip || seg->vmsize == 0) {
                    lc += cmd->cmdsize;
                    continue;
                }

                uint8_t * const segBase = (uint8_t *)(uintptr_t)(seg->vmaddr + slide);
                const uint64_t  segSize = seg->vmsize;

                for (uint64_t off = 0; off + kPatLen <= segSize; off++) {

                    if (memcmp(segBase + off, kFind, kPatLen) != 0) continue;

                    uint8_t *target = segBase + off;

                    // Unlock page
                    kern_return_t kr = setProt(target, kPatLen,
                                               VM_PROT_READ | VM_PROT_WRITE);
                    if (kr != KERN_SUCCESS) {
                        NSLog(@"[SwipePatcher] vm_protect RW failed @ %p (kr=%d)",
                              (void *)target, kr);
                        continue;
                    }

                    memcpy(target, kReplace, kPatLen);
                    __sync_synchronize(); // full memory barrier

                    // Restore protection
                    vm_prot_t restoreProt = (kind == kSegText)
                        ? (VM_PROT_READ | VM_PROT_EXECUTE)
                        : (VM_PROT_READ | VM_PROT_WRITE);
                    setProt(target, kPatLen, restoreProt);

                    hits++;
                    NSLog(@"[SwipePatcher] ✓ patched @ %p in %s %s",
                          (void *)target,
                          _dyld_get_image_name(imgIdx),
                          seg->segname);
                }
            }

            lc += cmd->cmdsize;
        }
    }

    return hits;
}

// ─── One-shot dispatch ────────────────────────────────────────────────────────
static void
triggerPatch(void) {
    // CAS: only the first upswipe wins the race
    bool expected = false;
    if (!atomic_compare_exchange_strong(&gPatchDone, &expected, true)) return;

    // Off main thread so we don't block UIKit
    dispatch_async(
        dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        uint32_t hits = scanAndPatch();
        if (hits == 0) {
            NSLog(@"[SwipePatcher] pattern not found — nothing patched");
        } else {
            NSLog(@"[SwipePatcher] done — %u site(s) patched", hits);
        }
    });
}

// ─── Touch interception (UIWindow — catches all touches in the process) ────────
%hook UIWindow

- (void)sendEvent:(UIEvent *)event {
    %orig; // let the app process first

    // Already fired — drop out immediately, zero overhead
    if (atomic_load_explicit(&gPatchDone, memory_order_relaxed)) return;

    NSSet<UITouch *> *touches = [event allTouches];
    if (!touches.count) return;

    UITouch  *touch = touches.anyObject;
    CGPoint   loc   = [touch locationInView:self];

    switch (touch.phase) {

        case UITouchPhaseBegan:
            // Anchor start position for this gesture
            gStartY   = loc.y;
            gTracking = YES;
            break;

        case UITouchPhaseMoved: {
            if (!gTracking) break;

            // deltaY > 0  →  finger moved upward on screen
            CGFloat deltaY = gStartY - loc.y;

            if (deltaY > kSwipeThreshold) {
                // Disarm tracking immediately — reject any subsequent moves
                gTracking = NO;
                triggerPatch();
            }
            break;
        }

        case UITouchPhaseEnded:
        case UITouchPhaseCancelled:
        case UITouchPhaseStationary:
            gTracking = NO;
            break;

        default:
            break;
    }
}

%end

// ─── Entry ────────────────────────────────────────────────────────────────────
%ctor {
    NSLog(@"[SwipePatcher] injected — swipe ↑ >%.0fpx to patch 'body'→'head'",
          kSwipeThreshold);
}
