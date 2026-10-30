import { afterEach, describe, expect, it } from '@rstest/core';
import { act, renderHook } from '@testing-library/react';
import { createGroupedSidebarItems } from 'utils/route-utils';

import type { EndpointCompatibility } from '../../state/rest-interfaces';
import { Feature, useSupportedFeaturesStore } from '../../state/supported-features';

describe('the SidebarNavigation re-renders on endpointCompatibility change (UX-972)', () => {
  afterEach(() => {
    // Reset store to initial state between tests
    useSupportedFeaturesStore.setState({
      endpointCompatibility: null,
      sqlApi: false,
    });
  });

  it('the SQLService defaults to unsupported when endpointCompatibility is null', () => {
    const state = useSupportedFeaturesStore.getState();
    expect(state.endpointCompatibility).toBeNull();
    expect(state.sqlApi).toBe(false);
  });

  it('the SQL item is hidden when SQLService is not supported', () => {
    const groups = createGroupedSidebarItems();
    const allItems = groups.flatMap((g) => g.items);
    const sql = allItems.find((item) => item.to === '/sql');
    expect(sql).toBeUndefined();
  });

  it('the SQL item appears after endpointCompatibility loads with SQLService supported', () => {
    const compatibility: EndpointCompatibility = {
      kafkaVersion: '3.6.0',
      endpoints: [
        {
          endpoint: Feature.SQLService.endpoint,
          method: Feature.SQLService.method,
          isSupported: true,
        },
      ],
    };

    act(() => {
      useSupportedFeaturesStore.getState().setEndpointCompatibility(compatibility);
    });

    const groups = createGroupedSidebarItems();
    const allItems = groups.flatMap((g) => g.items);
    const sql = allItems.find((item) => item.to === '/sql');
    expect(sql).toBeDefined();
    expect(sql?.title).toBe('SQL');
  });

  it('store selector triggers re-render when endpointCompatibility changes', async () => {
    const selector = (s: { endpointCompatibility: EndpointCompatibility | null }) => s.endpointCompatibility;
    const { result, unmount } = renderHook(() => useSupportedFeaturesStore(selector));

    expect(result.current).toBeNull();

    const compatibility: EndpointCompatibility = {
      kafkaVersion: '3.6.0',
      endpoints: [
        {
          endpoint: Feature.SQLService.endpoint,
          method: Feature.SQLService.method,
          isSupported: true,
        },
      ],
    };

    // Zustand's useSyncExternalStore subscriber schedules the re-render
    // synchronously, but renderHook's TestComponent runs a trailing useEffect
    // to sync `result.current`. Await act() around the store mutation so
    // the boundary awaits the microtask + effect flush before the assertion.
    await act(() => {
      useSupportedFeaturesStore.getState().setEndpointCompatibility(compatibility);
    });

    expect(result.current).toBe(compatibility);

    // Unmount before the afterEach's store reset fires, otherwise the
    // reset triggers an update on the still-mounted TestComponent outside
    // any act boundary and emits the "not wrapped in act(...)" warning.
    unmount();
  });
});

describe('the sidebar hides disabled features', () => {
  const featurePaths = ['/schema-registry', '/connect-clusters', '/transforms', '/shadowlinks', '/reassign-partitions'];
  const visiblePaths = () =>
    createGroupedSidebarItems()
      .flatMap((g) => g.items)
      .map((item) => item.to);
  const withSupport = (isSupported: boolean): EndpointCompatibility => ({
    kafkaVersion: '3.6.0',
    endpoints: [
      Feature.SchemaRegistry,
      Feature.KafkaConnect,
      Feature.PipelineService,
      Feature.TransformsService,
      Feature.ShadowLinkService,
      Feature.GetReassignments,
      Feature.PatchReassignments,
    ].map((f) => ({ endpoint: f.endpoint, method: f.method, isSupported })),
  });

  afterEach(() => {
    useSupportedFeaturesStore.setState({ endpointCompatibility: null });
  });

  it('hides all of them when the backend reports them as unsupported', () => {
    act(() => {
      useSupportedFeaturesStore.getState().setEndpointCompatibility(withSupport(false));
    });

    const paths = visiblePaths();
    for (const path of featurePaths) {
      expect(paths).not.toContain(path);
    }
  });

  it('shows the supported ones, except reassign partitions without the REASSIGN_PARTITIONS app feature', () => {
    act(() => {
      useSupportedFeaturesStore.getState().setEndpointCompatibility(withSupport(true));
    });

    const paths = visiblePaths();
    for (const path of ['/schema-registry', '/connect-clusters', '/transforms', '/shadowlinks']) {
      expect(paths).toContain(path);
    }
    expect(paths).not.toContain('/reassign-partitions');
  });

  it('shows schema registry and connect when an older backend does not report them', () => {
    act(() => {
      useSupportedFeaturesStore.getState().setEndpointCompatibility({ kafkaVersion: '3.6.0', endpoints: [] });
    });

    const paths = visiblePaths();
    expect(paths).toContain('/schema-registry');
    expect(paths).toContain('/connect-clusters');
  });
});
