import ImageDetailPage from '@/app/image/[id]/page';
import '@testing-library/jest-dom';
import { render } from '@testing-library/react';
import { act } from 'react';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ replace: () => {} }),
}));

jest.mock('../../../contexts/auth', () => ({
  useAuth: jest.fn(() => ({ state: { accessToken: 'abc', isLoading: false } })),
}));

jest.mock('../../../client/', () => ({
  mediaDetailMediaDetailGet: jest.fn(() => ({})),
}));

describe('ImageDetailPage', () => {
  it('renders unchanged', async () => {
    let container;
    await act(async () => {
      const result = render(
        <ImageDetailPage
          params={new Promise((resolve) => resolve({ id: 'abc' }))}
        />
      );

      container = result.container;
    });

    expect(container).toMatchSnapshot();
  });
});
