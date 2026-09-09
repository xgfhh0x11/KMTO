//
// KMTO — Windows kernel driver entry point and IOCTL dispatcher.
//
// v2 surface:
//   IRP_MJ_CREATE / IRP_MJ_CLOSE                       — open / close
//   IRP_MJ_DEVICE_CONTROL
//     KMTO_IOCTL_HANDSHAKE          (0x900) — protocol exchange
//     KMTO_IOCTL_GET_CR4_SNAPSHOT   (0x901) — synchronous CR4/MSR read
//     KMTO_IOCTL_GET_EVENTS         (0x902) — drain a CPU's ring
//     KMTO_IOCTL_GET_STATS          (0x903) — aggregate counters
//     KMTO_IOCTL_RESET              (0x904) — clear rings + counters
//     KMTO_IOCTL_CONFIGURE          (0x905) — sampler + bugcheck cb
//
// The driver implements *only* these six IOCTLs and the create/close
// pair. No SSDT hook, no page-table write, no privileged register
// write, no exception-handler injection. The data flow is one-way
// (kernel → userland) via the per-CPU ring buffer.
//

#include <ntddk.h>
#include <ntstrsafe.h>
#include "../include/kmto_protocol.h"
#include "../include/kmto_kernel_state.h"

// Singleton observer state — referenced by event_ring.c and
// cr4_observer.c via the extern declaration in kmto_kernel_state.h.
KMTO_OBSERVER_STATE g_KmtoState = { 0 };

static PDEVICE_OBJECT g_DeviceObject = NULL;
static UNICODE_STRING g_SymbolicLink;

// -----------------------------------------------------------------
// Forward decls
// -----------------------------------------------------------------

static DRIVER_UNLOAD              KmtoUnload;
static DRIVER_DISPATCH            KmtoCreateClose;
static DRIVER_DISPATCH            KmtoDeviceControl;

static NTSTATUS KmtopCompleteIrp(_In_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Information);
static VOID     KmtopFillHandshake(_In_ const kmto_handshake_request_t *Request,
                                   _Out_ kmto_handshake_response_t *Response);
static NTSTATUS KmtopHandleGetEvents(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack, _Out_ PULONG_PTR OutInfo);
static NTSTATUS KmtopHandleGetCr4(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack, _Out_ PULONG_PTR OutInfo);
static NTSTATUS KmtopHandleGetStats(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack, _Out_ PULONG_PTR OutInfo);
static NTSTATUS KmtopHandleReset(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack, _Out_ PULONG_PTR OutInfo);
static NTSTATUS KmtopHandleConfigure(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack, _Out_ PULONG_PTR OutInfo);

// -----------------------------------------------------------------
// DriverEntry / unload
// -----------------------------------------------------------------

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLink;
    ULONG64 initEvent[5] = { 0 };

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&deviceName, KMTO_DEVICE_NAME);
    RtlInitUnicodeString(&symLink,    KMTO_SYMLINK_NAME);
    RtlInitUnicodeString(&g_SymbolicLink, KMTO_SYMLINK_NAME);

    status = IoCreateDevice(DriverObject, 0, &deviceName,
                            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                            FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->DriverUnload                         = KmtoUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = KmtoCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = KmtoCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KmtoDeviceControl;

    // Bring up per-CPU ring then observer (sampler/timer/DPCs/cb record).
    status = KmtoRingInit(&g_KmtoState);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&g_SymbolicLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    status = KmtoObserverInit(&g_KmtoState);
    if (!NT_SUCCESS(status)) {
        KmtoRingCleanup(&g_KmtoState);
        IoDeleteSymbolicLink(&g_SymbolicLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    // First event in every CPU's ring marks driver load.
    {
        ULONG cpu, cpuCount = g_KmtoState.ProcessorCount;
        initEvent[0] = (ULONG64)KMTO_PROTOCOL_VERSION;
        for (cpu = 0; cpu < cpuCount; cpu++) {
            KmtoRingWrite(&g_KmtoState, cpu, KMTO_EVT_DRIVER_INIT, initEvent);
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KMTO] Driver loaded (v0x%08X, %lu CPUs)\n",
               KMTO_PROTOCOL_VERSION, g_KmtoState.ProcessorCount);

    return STATUS_SUCCESS;
}

static VOID
KmtoUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    ULONG64 stopEvent[5] = { 0 };
    ULONG cpu, cpuCount;

    UNREFERENCED_PARAMETER(DriverObject);

    cpuCount = g_KmtoState.ProcessorCount;
    for (cpu = 0; cpu < cpuCount; cpu++) {
        KmtoRingWrite(&g_KmtoState, cpu, KMTO_EVT_DRIVER_STOP, stopEvent);
    }

    KmtoObserverCleanup(&g_KmtoState);
    KmtoRingCleanup(&g_KmtoState);

    if (g_DeviceObject) {
        IoDeleteSymbolicLink(&g_SymbolicLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[KMTO] Driver unloaded\n");
}

// -----------------------------------------------------------------
// Dispatch helpers
// -----------------------------------------------------------------

static NTSTATUS
KmtopCompleteIrp(_In_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS
KmtoCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return KmtopCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static VOID
KmtopFillHandshake(_In_ const kmto_handshake_request_t *Request,
                   _Out_ kmto_handshake_response_t *Response)
{
    LARGE_INTEGER qpc;

    RtlZeroMemory(Response, sizeof(*Response));
    Response->status        = KMTO_HANDSHAKE_OK;
    Response->driver_build  = 0x20251118;

    qpc = KeQueryPerformanceCounter(NULL);
    Response->session_token =
        (ULONG64)MmGetPhysicalAddress((PVOID)Response).QuadPart ^
        (ULONG64)qpc.QuadPart;

    RtlStringCbCopyA(Response->author, sizeof(Response->author), "Tylersec");
    RtlStringCbCopyA(Response->banner, sizeof(Response->banner),
                     "KMTO: SMEP/SMAP+PAC telemetry observatory (v2)");

    UNREFERENCED_PARAMETER(Request);
}

// -----------------------------------------------------------------
// IOCTL handlers — one per IOCTL, each fills *OutInfo with the
// response byte count on success.
// -----------------------------------------------------------------

static NTSTATUS
KmtopHandleGetCr4(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack, _Out_ PULONG_PTR OutInfo)
{
    kmto_cr4_snapshot_t *resp;

    *OutInfo = 0;

    if (Stack->Parameters.DeviceIoControl.OutputBufferLength <
            sizeof(kmto_cr4_snapshot_t)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    resp = (kmto_cr4_snapshot_t *)Irp->AssociatedIrp.SystemBuffer;
    if (!resp) {
        return STATUS_INVALID_PARAMETER;
    }

    KmtoReadCr4Snapshot(resp);
    *OutInfo = sizeof(kmto_cr4_snapshot_t);
    return STATUS_SUCCESS;
}

static NTSTATUS
KmtopHandleGetEvents(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack, _Out_ PULONG_PTR OutInfo)
{
    kmto_get_events_request_t  reqLocal;
    kmto_get_events_response_t *resp;
    SIZE_T  outAvail;
    SIZE_T  hdrSize;
    SIZE_T  slotCap;
    ULONG   maxEvents;
    ULONG   drained;
    ULONG64 lost = 0;

    *OutInfo = 0;

    if (Stack->Parameters.DeviceIoControl.InputBufferLength <
            sizeof(kmto_get_events_request_t)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // METHOD_BUFFERED — input and output share Irp->AssociatedIrp.SystemBuffer.
    // Copy the request out before we start writing the response into the
    // same buffer.
    RtlCopyMemory(&reqLocal,
                  Irp->AssociatedIrp.SystemBuffer,
                  sizeof(reqLocal));

    outAvail = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    hdrSize  = FIELD_OFFSET(kmto_get_events_response_t, events);
    if (outAvail < hdrSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    slotCap = (outAvail - hdrSize) / sizeof(kmto_event_t);
    if (slotCap == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    maxEvents = (reqLocal.max_events < (ULONG)slotCap)
                ? reqLocal.max_events : (ULONG)slotCap;

    resp = (kmto_get_events_response_t *)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(resp, hdrSize);

    drained = KmtoRingDrain(&g_KmtoState, reqLocal.cpu_number,
                            maxEvents, resp->events, &lost);
    resp->event_count = drained;
    resp->lost_events = (ULONG)lost;

    *OutInfo = hdrSize + (SIZE_T)drained * sizeof(kmto_event_t);
    return STATUS_SUCCESS;
}

static NTSTATUS
KmtopHandleGetStats(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack, _Out_ PULONG_PTR OutInfo)
{
    kmto_stats_t *resp;

    *OutInfo = 0;

    if (Stack->Parameters.DeviceIoControl.OutputBufferLength <
            sizeof(kmto_stats_t)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    resp = (kmto_stats_t *)Irp->AssociatedIrp.SystemBuffer;
    if (!resp) {
        return STATUS_INVALID_PARAMETER;
    }

    KmtoStatsSnapshot(&g_KmtoState, resp);
    *OutInfo = sizeof(kmto_stats_t);
    return STATUS_SUCCESS;
}

static NTSTATUS
KmtopHandleReset(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack, _Out_ PULONG_PTR OutInfo)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(Stack);

    *OutInfo = 0;
    KmtoRingReset(&g_KmtoState);

    // Reset cumulative stat counters too — the per-CPU counters
    // were cleared by KmtoRingReset.
    g_KmtoState.Stats.cr4_samples      = 0;
    g_KmtoState.Stats.msr_samples      = 0;
    g_KmtoState.Stats.bugcheck_events  = 0;

    return STATUS_SUCCESS;
}

static NTSTATUS
KmtopHandleConfigure(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack, _Out_ PULONG_PTR OutInfo)
{
    kmto_configure_request_t  reqLocal;
    kmto_configure_response_t *resp;
    ULONG activeMask = 0;
    ULONG intervalMs = 0;
    NTSTATUS status;

    *OutInfo = 0;

    if (Stack->Parameters.DeviceIoControl.InputBufferLength <
            sizeof(kmto_configure_request_t) ||
        Stack->Parameters.DeviceIoControl.OutputBufferLength <
            sizeof(kmto_configure_response_t)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(&reqLocal,
                  Irp->AssociatedIrp.SystemBuffer,
                  sizeof(reqLocal));

    status = KmtoObserverConfigure(&g_KmtoState,
                                   reqLocal.enable_mask,
                                   reqLocal.sampling_interval_ms,
                                   &activeMask, &intervalMs);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    resp = (kmto_configure_response_t *)Irp->AssociatedIrp.SystemBuffer;
    resp->active_mask          = activeMask;
    resp->sampling_interval_ms = intervalMs;
    *OutInfo = sizeof(kmto_configure_response_t);
    return STATUS_SUCCESS;
}

// -----------------------------------------------------------------
// IRP_MJ_DEVICE_CONTROL dispatcher
// -----------------------------------------------------------------

static NTSTATUS
KmtoDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    ULONG    code;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    code  = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (code) {

    case KMTO_IOCTL_HANDSHAKE: {
        const kmto_handshake_request_t *request;
        kmto_handshake_response_t      *response;

        if (stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(kmto_handshake_request_t) ||
            stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(kmto_handshake_response_t)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        request  = (const kmto_handshake_request_t *)Irp->AssociatedIrp.SystemBuffer;
        response = (kmto_handshake_response_t *)Irp->AssociatedIrp.SystemBuffer;

        if (request->version != KMTO_PROTOCOL_VERSION &&
            request->version != 0x00010000) {  // accept v1 clients with degraded mode
            RtlZeroMemory(response, sizeof(*response));
            response->status = KMTO_HANDSHAKE_ERR_PROTO;
        } else {
            KmtopFillHandshake(request, response);
        }
        information = sizeof(kmto_handshake_response_t);
        status = STATUS_SUCCESS;
        break;
    }

    case KMTO_IOCTL_GET_CR4_SNAPSHOT:
        status = KmtopHandleGetCr4(Irp, stack, &information);
        break;

    case KMTO_IOCTL_GET_EVENTS:
        status = KmtopHandleGetEvents(Irp, stack, &information);
        break;

    case KMTO_IOCTL_GET_STATS:
        status = KmtopHandleGetStats(Irp, stack, &information);
        break;

    case KMTO_IOCTL_RESET:
        status = KmtopHandleReset(Irp, stack, &information);
        break;

    case KMTO_IOCTL_CONFIGURE:
        status = KmtopHandleConfigure(Irp, stack, &information);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        information = 0;
        break;
    }

    return KmtopCompleteIrp(Irp, status, information);
}
